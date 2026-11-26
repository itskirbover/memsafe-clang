#include "memsafe/Checks.h"

#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Analysis/CFG.h>

#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

namespace memsafe {
namespace {

using VarSet = std::set<const clang::VarDecl *>;

const clang::VarDecl *extractVarDecl(const clang::Expr *expr) {
  if (!expr) {
    return nullptr;
  }
  const clang::Expr *stripped = expr->IgnoreParenImpCasts();
  if (const auto *dre = llvm::dyn_cast<clang::DeclRefExpr>(stripped)) {
    return llvm::dyn_cast<clang::VarDecl>(dre->getDecl());
  }
  return nullptr;
}

bool isFreeCall(const clang::CallExpr *call) {
  const clang::FunctionDecl *callee = call->getDirectCallee();
  if (!callee || !callee->getIdentifier()) {
    return false;
  }
  return callee->getName() == "free" && call->getNumArgs() >= 1;
}

class UseAfterFreeAnalyzer {
public:
  UseAfterFreeAnalyzer(clang::ASTContext &ctx, DiagnosticReporter &reporter)
      : ctx_(ctx), reporter_(reporter) {}

  void analyzeFunction(const clang::FunctionDecl *fn) {
    if (!fn->doesThisDeclarationHaveABody() || fn->isDependentContext()) {
      return;
    }
    clang::SourceLocation loc = fn->getLocation();
    if (loc.isInvalid() || ctx_.getSourceManager().isInSystemHeader(loc)) {
      return;
    }

    clang::CFG::BuildOptions cfgOpts;
    cfgOpts.AddImplicitDtors = false;
    cfgOpts.AddTemporaryDtors = false;

    std::unique_ptr<clang::CFG> cfg =
        clang::CFG::buildCFG(fn, fn->getBody(), &ctx_, cfgOpts);
    if (!cfg) {
      return;
    }

    std::unordered_map<unsigned, VarSet> blockIn;
    std::unordered_map<unsigned, VarSet> blockOut;
    std::set<unsigned> reachable;

    std::queue<const clang::CFGBlock *> worklist;
    const clang::CFGBlock &entry = cfg->getEntry();
    worklist.push(&entry);
    reachable.insert(entry.getBlockID());

    // Forward may-analysis fixpoint over CFG
    while (!worklist.empty()) {
      const clang::CFGBlock *block = worklist.front();
      worklist.pop();

      unsigned id = block->getBlockID();
      VarSet state = blockIn[id];

      for (const clang::CFGElement &elem : *block) {
        auto stmtElem = elem.getAs<clang::CFGStmt>();
        if (!stmtElem) {
          continue;
        }
        transferStmt(stmtElem->getStmt(), state, /*emitDiags=*/false);
      }

      auto outIt = blockOut.find(id);
      bool changed = (outIt == blockOut.end()) || (outIt->second != state);
      if (changed) {
        blockOut[id] = state;
        for (const clang::CFGBlock::AdjacentBlock &succ : block->succs()) {
          if (!succ) {
            continue;
          }
          unsigned succId = succ->getBlockID();
          reachable.insert(succId);
          VarSet &succIn = blockIn[succId];
          size_t before = succIn.size();
          succIn.insert(state.begin(), state.end());
          if (succIn.size() != before || !blockOut.count(succId)) {
            worklist.push(succ);
          }
        }
      }
    }

    // Final diagnostic pass on converged states
    reported_.clear();
    for (const clang::CFGBlock *block : *cfg) {
      if (!block || !reachable.count(block->getBlockID())) {
        continue;
      }
      VarSet state = blockIn[block->getBlockID()];
      for (const clang::CFGElement &elem : *block) {
        auto stmtElem = elem.getAs<clang::CFGStmt>();
        if (!stmtElem) {
          continue;
        }
        transferStmt(stmtElem->getStmt(), state, /*emitDiags=*/true);
      }
    }
  }

private:
  void reportOnce(clang::SourceLocation loc, const clang::VarDecl *vd,
                  const std::string &cwe, const std::string &msg) {
    auto key = std::make_pair(loc.getRawEncoding(), vd);
    if (reported_.insert(key).second) {
      reporter_.report(loc, "use-after-free", cwe, msg);
    }
  }

  void transferStmt(const clang::Stmt *stmt, VarSet &freed, bool emitDiags) {
    if (!stmt) {
      return;
    }

    // Pointer reassignment: evaluate RHS first, then clear LHS if it's a direct
    // pointer variable (otherwise recurse into LHS e.g. *p = 42).
    if (const auto *bo = llvm::dyn_cast<clang::BinaryOperator>(stmt)) {
      if (bo->getOpcode() == clang::BO_Assign) {
        transferStmt(bo->getRHS(), freed, emitDiags);
        if (const clang::VarDecl *lhs = extractVarDecl(bo->getLHS())) {
          if (lhs->getType()->isPointerType()) {
            freed.erase(lhs);
            return;
          }
        }
        transferStmt(bo->getLHS(), freed, emitDiags);
        return;
      }
    }

    // Dereference: *p
    if (const auto *uo = llvm::dyn_cast<clang::UnaryOperator>(stmt)) {
      if (uo->getOpcode() == clang::UO_Deref) {
        if (const clang::VarDecl *vd = extractVarDecl(uo->getSubExpr())) {
          if (freed.count(vd) && emitDiags) {
            reportOnce(uo->getBeginLoc(), vd, "CWE-416",
                       "use of pointer '" + vd->getNameAsString() +
                           "' after it was freed");
          }
        }
      }
      transferStmt(uo->getSubExpr(), freed, emitDiags);
      return;
    }

    // Subscript: p[i]
    if (const auto *ase = llvm::dyn_cast<clang::ArraySubscriptExpr>(stmt)) {
      if (const clang::VarDecl *vd = extractVarDecl(ase->getBase())) {
        if (freed.count(vd) && emitDiags) {
          reportOnce(ase->getBeginLoc(), vd, "CWE-416",
                     "subscript of pointer '" + vd->getNameAsString() +
                         "' after it was freed");
        }
      }
      transferStmt(ase->getBase(), freed, emitDiags);
      transferStmt(ase->getIdx(), freed, emitDiags);
      return;
    }

    // Arrow member access: p->field
    if (const auto *me = llvm::dyn_cast<clang::MemberExpr>(stmt)) {
      if (me->isArrow()) {
        if (const clang::VarDecl *vd = extractVarDecl(me->getBase())) {
          if (freed.count(vd) && emitDiags) {
            reportOnce(me->getBeginLoc(), vd, "CWE-416",
                       "member access on pointer '" + vd->getNameAsString() +
                           "' after it was freed");
          }
        }
      }
      transferStmt(me->getBase(), freed, emitDiags);
      return;
    }

    // C++ delete / delete[]
    if (const auto *del = llvm::dyn_cast<clang::CXXDeleteExpr>(stmt)) {
      if (const clang::VarDecl *vd = extractVarDecl(del->getArgument())) {
        if (freed.count(vd)) {
          if (emitDiags) {
            reportOnce(del->getBeginLoc(), vd, "CWE-415",
                       "double-free: pointer '" + vd->getNameAsString() +
                           "' has already been deleted");
          }
        } else {
          freed.insert(vd);
        }
      }
      return;
    }

    // Function calls: free(p) or passing freed pointer to another function
    if (const auto *call = llvm::dyn_cast<clang::CallExpr>(stmt)) {
      if (isFreeCall(call)) {
        if (const clang::VarDecl *vd = extractVarDecl(call->getArg(0))) {
          if (freed.count(vd)) {
            if (emitDiags) {
              reportOnce(call->getBeginLoc(), vd, "CWE-415",
                         "double-free: pointer '" + vd->getNameAsString() +
                             "' has already been freed");
            }
          } else {
            freed.insert(vd);
          }
        }
        return;
      }

      for (const clang::Expr *arg : call->arguments()) {
        if (const clang::VarDecl *vd = extractVarDecl(arg)) {
          if (vd->getType()->isPointerType() && freed.count(vd) && emitDiags) {
            reportOnce(arg->getBeginLoc(), vd, "CWE-416",
                       "passing freed pointer '" + vd->getNameAsString() +
                           "' to function call");
          }
        } else {
          transferStmt(arg, freed, emitDiags);
        }
      }
      return;
    }

    // Declaration statements: inspect variable initializers
    if (const auto *ds = llvm::dyn_cast<clang::DeclStmt>(stmt)) {
      for (const clang::Decl *d : ds->decls()) {
        if (const auto *vd = llvm::dyn_cast<clang::VarDecl>(d)) {
          if (const clang::Expr *init = vd->getInit()) {
            transferStmt(init, freed, emitDiags);
          }
          freed.erase(vd);
        }
      }
      return;
    }

    // Recurse into child expressions for other statement wrappers (e.g.
    // ReturnStmt, ImplicitCastExpr, ParenExpr, etc.)
    for (const clang::Stmt *child : stmt->children()) {
      transferStmt(child, freed, emitDiags);
    }
  }

  clang::ASTContext &ctx_;
  DiagnosticReporter &reporter_;
  std::set<std::pair<unsigned, const clang::VarDecl *>> reported_;
};

class UseAfterFreeVisitor
    : public clang::RecursiveASTVisitor<UseAfterFreeVisitor> {
public:
  UseAfterFreeVisitor(clang::ASTContext &ctx, DiagnosticReporter &reporter)
      : analyzer_(ctx, reporter) {}

  bool VisitFunctionDecl(clang::FunctionDecl *fn) {
    analyzer_.analyzeFunction(fn);
    return true;
  }

private:
  UseAfterFreeAnalyzer analyzer_;
};

class UseAfterFreeCheck : public MemorySafetyCheck {
public:
  std::string name() const override { return "use-after-free"; }

  void run(clang::ASTContext &ctx, DiagnosticReporter &reporter) override {
    UseAfterFreeVisitor visitor(ctx, reporter);
    visitor.TraverseDecl(ctx.getTranslationUnitDecl());
  }
};

} // namespace

std::unique_ptr<MemorySafetyCheck> createUseAfterFreeCheck() {
  return std::make_unique<UseAfterFreeCheck>();
}

} // namespace memsafe
