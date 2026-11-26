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

class UninitializedPointerAnalyzer {
public:
  UninitializedPointerAnalyzer(clang::ASTContext &ctx,
                               DiagnosticReporter &reporter)
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

    // Forward may-uninitialized fixpoint over CFG
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
      reporter_.report(loc, "uninitialized-pointer", cwe, msg);
    }
  }

  void transferStmt(const clang::Stmt *stmt, VarSet &uninit, bool emitDiags) {
    if (!stmt) {
      return;
    }

    // Track local uninitialized pointer declarations
    if (const auto *ds = llvm::dyn_cast<clang::DeclStmt>(stmt)) {
      for (const clang::Decl *d : ds->decls()) {
        if (const auto *vd = llvm::dyn_cast<clang::VarDecl>(d)) {
          if (!vd->hasLocalStorage() || vd->isStaticLocal()) {
            continue;
          }
          if (vd->hasInit()) {
            transferStmt(vd->getInit(), uninit, emitDiags);
            uninit.erase(vd);
          } else if (vd->getType()->isPointerType()) {
            uninit.insert(vd);
          }
        }
      }
      return;
    }

    // Assignment initializes a pointer variable: evaluate RHS first
    if (const auto *bo = llvm::dyn_cast<clang::BinaryOperator>(stmt)) {
      if (bo->getOpcode() == clang::BO_Assign) {
        transferStmt(bo->getRHS(), uninit, emitDiags);
        if (const clang::VarDecl *lhs = extractVarDecl(bo->getLHS())) {
          if (lhs->getType()->isPointerType()) {
            uninit.erase(lhs);
            return;
          }
        }
        transferStmt(bo->getLHS(), uninit, emitDiags);
        return;
      }
    }

    // Dereference: *p
    if (const auto *uo = llvm::dyn_cast<clang::UnaryOperator>(stmt)) {
      if (uo->getOpcode() == clang::UO_Deref) {
        if (const clang::VarDecl *vd = extractVarDecl(uo->getSubExpr())) {
          if (uninit.count(vd) && emitDiags) {
            reportOnce(uo->getBeginLoc(), vd, "CWE-824",
                       "dereference of uninitialized pointer '" +
                           vd->getNameAsString() + "'");
          }
        }
      }
      transferStmt(uo->getSubExpr(), uninit, emitDiags);
      return;
    }

    // Subscript: p[i]
    if (const auto *ase = llvm::dyn_cast<clang::ArraySubscriptExpr>(stmt)) {
      if (const clang::VarDecl *vd = extractVarDecl(ase->getBase())) {
        if (uninit.count(vd) && emitDiags) {
          reportOnce(ase->getBeginLoc(), vd, "CWE-824",
                     "subscript of uninitialized pointer '" +
                         vd->getNameAsString() + "'");
        }
      }
      transferStmt(ase->getBase(), uninit, emitDiags);
      transferStmt(ase->getIdx(), uninit, emitDiags);
      return;
    }

    // Arrow member access: p->field
    if (const auto *me = llvm::dyn_cast<clang::MemberExpr>(stmt)) {
      if (me->isArrow()) {
        if (const clang::VarDecl *vd = extractVarDecl(me->getBase())) {
          if (uninit.count(vd) && emitDiags) {
            reportOnce(me->getBeginLoc(), vd, "CWE-824",
                       "member access on uninitialized pointer '" +
                           vd->getNameAsString() + "'");
          }
        }
      }
      transferStmt(me->getBase(), uninit, emitDiags);
      return;
    }

    // Deleting an uninitialized pointer
    if (const auto *del = llvm::dyn_cast<clang::CXXDeleteExpr>(stmt)) {
      if (const clang::VarDecl *vd = extractVarDecl(del->getArgument())) {
        if (uninit.count(vd) && emitDiags) {
          reportOnce(del->getBeginLoc(), vd, "CWE-457",
                     "deleting uninitialized pointer '" +
                         vd->getNameAsString() + "'");
        }
      }
      return;
    }

    // Freeing an uninitialized pointer
    if (const auto *call = llvm::dyn_cast<clang::CallExpr>(stmt)) {
      const clang::FunctionDecl *callee = call->getDirectCallee();
      if (callee && callee->getIdentifier() && callee->getName() == "free" &&
          call->getNumArgs() >= 1) {
        if (const clang::VarDecl *vd = extractVarDecl(call->getArg(0))) {
          if (uninit.count(vd) && emitDiags) {
            reportOnce(call->getBeginLoc(), vd, "CWE-457",
                       "freeing uninitialized pointer '" +
                           vd->getNameAsString() + "'");
          }
        }
        return;
      }
      for (const clang::Expr *arg : call->arguments()) {
        transferStmt(arg, uninit, emitDiags);
      }
      return;
    }

    for (const clang::Stmt *child : stmt->children()) {
      transferStmt(child, uninit, emitDiags);
    }
  }

  clang::ASTContext &ctx_;
  DiagnosticReporter &reporter_;
  std::set<std::pair<unsigned, const clang::VarDecl *>> reported_;
};

class UninitializedPointerVisitor
    : public clang::RecursiveASTVisitor<UninitializedPointerVisitor> {
public:
  UninitializedPointerVisitor(clang::ASTContext &ctx,
                              DiagnosticReporter &reporter)
      : analyzer_(ctx, reporter) {}

  bool VisitFunctionDecl(clang::FunctionDecl *fn) {
    analyzer_.analyzeFunction(fn);
    return true;
  }

private:
  UninitializedPointerAnalyzer analyzer_;
};

class UninitializedPointerCheck : public MemorySafetyCheck {
public:
  std::string name() const override { return "uninitialized-pointer"; }

  void run(clang::ASTContext &ctx, DiagnosticReporter &reporter) override {
    UninitializedPointerVisitor visitor(ctx, reporter);
    visitor.TraverseDecl(ctx.getTranslationUnitDecl());
  }
};

} // namespace

std::unique_ptr<MemorySafetyCheck> createUninitializedPointerCheck() {
  return std::make_unique<UninitializedPointerCheck>();
}

} // namespace memsafe
