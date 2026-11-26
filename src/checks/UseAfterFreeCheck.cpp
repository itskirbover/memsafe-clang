#include "memsafe/Checks.h"

#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Analysis/CFG.h>

#include <map>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

namespace memsafe {
namespace {

using VarSet = std::set<const clang::VarDecl *>;

struct UafState {
  VarSet freed;
  std::map<const clang::VarDecl *, VarSet> aliases;

  bool operator==(const UafState &other) const {
    return freed == other.freed && aliases == other.aliases;
  }
  bool operator!=(const UafState &other) const { return !(*this == other); }

  bool mergeFrom(const UafState &other) {
    bool changed = false;
    for (const clang::VarDecl *v : other.freed) {
      if (freed.insert(v).second) {
        changed = true;
      }
    }
    for (const auto &[k, vals] : other.aliases) {
      VarSet &dst = aliases[k];
      for (const clang::VarDecl *a : vals) {
        if (dst.insert(a).second) {
          changed = true;
        }
      }
    }
    return changed;
  }

  void breakAliases(const clang::VarDecl *vd) {
    auto it = aliases.find(vd);
    if (it == aliases.end()) {
      return;
    }
    for (const clang::VarDecl *peer : it->second) {
      auto peerIt = aliases.find(peer);
      if (peerIt != aliases.end()) {
        peerIt->second.erase(vd);
        if (peerIt->second.empty()) {
          aliases.erase(peerIt);
        }
      }
    }
    aliases.erase(it);
  }

  void addAlias(const clang::VarDecl *a, const clang::VarDecl *b) {
    if (!a || !b || a == b) {
      return;
    }
    // Collect b's entire equivalence neighborhood so transitive aliases work
    VarSet group = {b};
    if (auto it = aliases.find(b); it != aliases.end()) {
      group.insert(it->second.begin(), it->second.end());
    }
    for (const clang::VarDecl *member : group) {
      if (member != a) {
        aliases[a].insert(member);
        aliases[member].insert(a);
      }
    }
  }

  void markFreedWithAliases(const clang::VarDecl *vd) {
    freed.insert(vd);
    if (auto it = aliases.find(vd); it != aliases.end()) {
      for (const clang::VarDecl *peer : it->second) {
        freed.insert(peer);
      }
    }
  }
};

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

bool isNullPointerExpr(const clang::Expr *expr, clang::ASTContext &ctx) {
  if (!expr) {
    return false;
  }
  return expr->isNullPointerConstant(ctx,
                                     clang::Expr::NPC_ValueDependentIsNotNull) !=
         clang::Expr::NPCK_NotNull;
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

    std::unordered_map<unsigned, UafState> blockIn;
    std::unordered_map<unsigned, UafState> blockOut;
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
      UafState state = blockIn[id];

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
          bool inChanged = blockIn[succId].mergeFrom(state);
          if (inChanged || !blockOut.count(succId)) {
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
      UafState state = blockIn[block->getBlockID()];
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

  void handlePointerAssign(const clang::VarDecl *lhs, const clang::Expr *rhs,
                           UafState &state) {
    state.breakAliases(lhs);
    if (isNullPointerExpr(rhs, ctx_)) {
      // Null-reset: free(nullptr) / delete nullptr is a safe no-op.
      state.freed.erase(lhs);
      return;
    }
    if (const clang::VarDecl *rhsVar = extractVarDecl(rhs)) {
      if (rhsVar->getType()->isPointerType()) {
        if (state.freed.count(rhsVar)) {
          state.freed.insert(lhs);
        } else {
          state.freed.erase(lhs);
        }
        state.addAlias(lhs, rhsVar);
        return;
      }
    }
    state.freed.erase(lhs);
  }

  void transferStmt(const clang::Stmt *stmt, UafState &state, bool emitDiags) {
    if (!stmt) {
      return;
    }

    // Pointer reassignment: evaluate RHS first, then update LHS state/aliases
    if (const auto *bo = llvm::dyn_cast<clang::BinaryOperator>(stmt)) {
      if (bo->getOpcode() == clang::BO_Assign) {
        transferStmt(bo->getRHS(), state, emitDiags);
        if (const clang::VarDecl *lhs = extractVarDecl(bo->getLHS())) {
          if (lhs->getType()->isPointerType()) {
            handlePointerAssign(lhs, bo->getRHS(), state);
            return;
          }
        }
        transferStmt(bo->getLHS(), state, emitDiags);
        return;
      }
    }

    // Dereference: *p
    if (const auto *uo = llvm::dyn_cast<clang::UnaryOperator>(stmt)) {
      if (uo->getOpcode() == clang::UO_Deref) {
        if (const clang::VarDecl *vd = extractVarDecl(uo->getSubExpr())) {
          if (state.freed.count(vd) && emitDiags) {
            reportOnce(uo->getBeginLoc(), vd, "CWE-416",
                       "use of pointer '" + vd->getNameAsString() +
                           "' after it was freed");
          }
        }
      }
      transferStmt(uo->getSubExpr(), state, emitDiags);
      return;
    }

    // Subscript: p[i]
    if (const auto *ase = llvm::dyn_cast<clang::ArraySubscriptExpr>(stmt)) {
      if (const clang::VarDecl *vd = extractVarDecl(ase->getBase())) {
        if (state.freed.count(vd) && emitDiags) {
          reportOnce(ase->getBeginLoc(), vd, "CWE-416",
                     "subscript of pointer '" + vd->getNameAsString() +
                         "' after it was freed");
        }
      }
      transferStmt(ase->getBase(), state, emitDiags);
      transferStmt(ase->getIdx(), state, emitDiags);
      return;
    }

    // Arrow member access: p->field
    if (const auto *me = llvm::dyn_cast<clang::MemberExpr>(stmt)) {
      if (me->isArrow()) {
        if (const clang::VarDecl *vd = extractVarDecl(me->getBase())) {
          if (state.freed.count(vd) && emitDiags) {
            reportOnce(me->getBeginLoc(), vd, "CWE-416",
                       "member access on pointer '" + vd->getNameAsString() +
                           "' after it was freed");
          }
        }
      }
      transferStmt(me->getBase(), state, emitDiags);
      return;
    }

    // C++ delete / delete[]
    if (const auto *del = llvm::dyn_cast<clang::CXXDeleteExpr>(stmt)) {
      if (isNullPointerExpr(del->getArgument(), ctx_)) {
        return;
      }
      if (const clang::VarDecl *vd = extractVarDecl(del->getArgument())) {
        if (state.freed.count(vd)) {
          if (emitDiags) {
            reportOnce(del->getBeginLoc(), vd, "CWE-415",
                       "double-free: pointer '" + vd->getNameAsString() +
                           "' has already been deleted");
          }
        } else {
          state.markFreedWithAliases(vd);
        }
      }
      return;
    }

    // Function calls: free(p), realloc(p, n), or passing freed pointer
    if (const auto *call = llvm::dyn_cast<clang::CallExpr>(stmt)) {
      if (isFreeCall(call)) {
        if (isNullPointerExpr(call->getArg(0), ctx_)) {
          return;
        }
        if (const clang::VarDecl *vd = extractVarDecl(call->getArg(0))) {
          if (state.freed.count(vd)) {
            if (emitDiags) {
              reportOnce(call->getBeginLoc(), vd, "CWE-415",
                         "double-free: pointer '" + vd->getNameAsString() +
                             "' has already been freed");
            }
          } else {
            state.markFreedWithAliases(vd);
          }
        }
        return;
      }

      for (const clang::Expr *arg : call->arguments()) {
        if (const clang::VarDecl *vd = extractVarDecl(arg)) {
          if (vd->getType()->isPointerType() && state.freed.count(vd) &&
              emitDiags) {
            reportOnce(arg->getBeginLoc(), vd, "CWE-416",
                       "passing freed pointer '" + vd->getNameAsString() +
                           "' to function call");
          }
        } else {
          transferStmt(arg, state, emitDiags);
        }
      }
      return;
    }

    // Declaration statements: inspect initializers and record pointer aliases
    if (const auto *ds = llvm::dyn_cast<clang::DeclStmt>(stmt)) {
      for (const clang::Decl *d : ds->decls()) {
        if (const auto *vd = llvm::dyn_cast<clang::VarDecl>(d)) {
          if (const clang::Expr *init = vd->getInit()) {
            transferStmt(init, state, emitDiags);
            if (vd->getType()->isPointerType()) {
              handlePointerAssign(vd, init, state);
            } else {
              state.freed.erase(vd);
            }
          } else {
            state.breakAliases(vd);
            state.freed.erase(vd);
          }
        }
      }
      return;
    }

    for (const clang::Stmt *child : stmt->children()) {
      transferStmt(child, state, emitDiags);
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
