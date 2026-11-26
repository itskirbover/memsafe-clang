#include "memsafe/Checks.h"

#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Type.h>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace memsafe {
namespace {

std::optional<int64_t> getStaticArrayByteSize(const clang::Expr *expr,
                                              clang::ASTContext &ctx) {
  if (!expr) {
    return std::nullopt;
  }
  const clang::Expr *stripped = expr->IgnoreParenImpCasts();
  if (const auto *arrTy = ctx.getAsConstantArrayType(stripped->getType())) {
    return ctx.getTypeSizeInChars(arrTy).getQuantity();
  }
  // Handle explicit &arr[0] or &arr
  if (const auto *uo = llvm::dyn_cast<clang::UnaryOperator>(stripped)) {
    if (uo->getOpcode() == clang::UO_AddrOf) {
      const clang::Expr *sub = uo->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *arrTy = ctx.getAsConstantArrayType(sub->getType())) {
        return ctx.getTypeSizeInChars(arrTy).getQuantity();
      }
      if (const auto *ase = llvm::dyn_cast<clang::ArraySubscriptExpr>(sub)) {
        const clang::Expr *base = ase->getBase()->IgnoreParenImpCasts();
        if (const auto *arrTy = ctx.getAsConstantArrayType(base->getType())) {
          clang::Expr::EvalResult idxVal;
          if (ase->getIdx()->EvaluateAsInt(idxVal, ctx) &&
              idxVal.Val.getInt().isZero()) {
            return ctx.getTypeSizeInChars(arrTy).getQuantity();
          }
        }
      }
    }
  }
  return std::nullopt;
}

std::string normalizeFuncName(llvm::StringRef raw) {
  if (raw.starts_with("__builtin_")) {
    raw = raw.drop_front(10);
  }
  if (raw.ends_with("_chk")) {
    raw = raw.drop_back(4);
  }
  return raw.str();
}

class BufferOverflowVisitor
    : public clang::RecursiveASTVisitor<BufferOverflowVisitor> {
public:
  BufferOverflowVisitor(clang::ASTContext &ctx, DiagnosticReporter &reporter)
      : ctx_(ctx), reporter_(reporter) {}

  bool VisitArraySubscriptExpr(clang::ArraySubscriptExpr *expr) {
    if (isInSystemHeader(expr->getBeginLoc())) {
      return true;
    }

    const clang::Expr *base = expr->getBase()->IgnoreParenImpCasts();
    const auto *arrTy = ctx_.getAsConstantArrayType(base->getType());
    if (!arrTy) {
      return true;
    }

    clang::Expr::EvalResult evalIdx;
    if (!expr->getIdx()->EvaluateAsInt(evalIdx, ctx_)) {
      return true;
    }

    int64_t index = evalIdx.Val.getInt().getSExtValue();
    uint64_t arraySize = arrTy->getSize().getZExtValue();

    if (index < 0 || static_cast<uint64_t>(index) >= arraySize) {
      reporter_.report(
          expr->getBeginLoc(), "buffer-overflow", "CWE-787",
          "out-of-bounds array index " + std::to_string(index) +
              " on array of size " + std::to_string(arraySize));
    }
    return true;
  }

  bool VisitCallExpr(clang::CallExpr *call) {
    if (isInSystemHeader(call->getBeginLoc())) {
      return true;
    }

    const clang::FunctionDecl *callee = call->getDirectCallee();
    if (!callee || !callee->getIdentifier()) {
      return true;
    }

    std::string fn = normalizeFuncName(callee->getName());

    // 1. Unsafe unbounded C string/buffer APIs
    static const std::unordered_map<std::string, std::string> unsafeApis = {
        {"gets", "use fgets() with an explicit buffer size instead"},
        {"strcpy", "use strncpy() or strlcpy() with explicit bounds instead"},
        {"strcat", "use strncat() or strlcat() with explicit bounds instead"},
        {"sprintf", "use snprintf() with an explicit buffer size instead"},
        {"vsprintf", "use vsnprintf() with an explicit buffer size instead"},
    };

    if (auto it = unsafeApis.find(fn); it != unsafeApis.end()) {
      // If strcpy(dst, "literal") overflows a known static array, report exact
      // byte sizes.
      if (fn == "strcpy" && call->getNumArgs() >= 2) {
        auto destBytes = getStaticArrayByteSize(call->getArg(0), ctx_);
        const auto *lit = llvm::dyn_cast<clang::StringLiteral>(
            call->getArg(1)->IgnoreParenImpCasts());
        if (destBytes && lit) {
          int64_t needed = static_cast<int64_t>(lit->getByteLength()) + 1;
          if (needed > *destBytes) {
            reporter_.report(
                call->getBeginLoc(), "buffer-overflow", "CWE-120",
                "strcpy() writes " + std::to_string(needed) +
                    " bytes (including NUL terminator) into buffer of size " +
                    std::to_string(*destBytes));
            return true;
          }
        }
      }
      reporter_.report(call->getBeginLoc(), "buffer-overflow", "CWE-120",
                       "call to unbounded function '" + fn + "()'; " +
                           it->second);
      return true;
    }

    // 2. Bounded copy/fill functions where constant size exceeds static buffer
    if ((fn == "memcpy" || fn == "memmove" || fn == "memset" ||
         fn == "strncpy" || fn == "strncat") &&
        call->getNumArgs() >= 3) {
      checkBoundedWrite(call, fn, 0, 2);
      return true;
    }

    if ((fn == "bzero" || fn == "snprintf") && call->getNumArgs() >= 2) {
      checkBoundedWrite(call, fn, 0, 1);
      return true;
    }

    return true;
  }

private:
  bool isInSystemHeader(clang::SourceLocation loc) const {
    return loc.isInvalid() || ctx_.getSourceManager().isInSystemHeader(loc);
  }

  void checkBoundedWrite(const clang::CallExpr *call, const std::string &fn,
                         unsigned dstIdx, unsigned sizeIdx) {
    auto destBytes = getStaticArrayByteSize(call->getArg(dstIdx), ctx_);
    if (!destBytes) {
      return;
    }

    clang::Expr::EvalResult sizeEval;
    if (!call->getArg(sizeIdx)->EvaluateAsInt(sizeEval, ctx_)) {
      return;
    }

    int64_t writeBytes = sizeEval.Val.getInt().getSExtValue();
    if (writeBytes < 0 || writeBytes > *destBytes) {
      reporter_.report(
          call->getBeginLoc(), "buffer-overflow", "CWE-120",
          fn + "() writes " + std::to_string(writeBytes) +
              " bytes into destination buffer of size " +
              std::to_string(*destBytes) + " bytes");
    }
  }

  clang::ASTContext &ctx_;
  DiagnosticReporter &reporter_;
};

class BufferOverflowCheck : public MemorySafetyCheck {
public:
  std::string name() const override { return "buffer-overflow"; }

  void run(clang::ASTContext &ctx, DiagnosticReporter &reporter) override {
    BufferOverflowVisitor visitor(ctx, reporter);
    visitor.TraverseDecl(ctx.getTranslationUnitDecl());
  }
};

} // namespace

std::unique_ptr<MemorySafetyCheck> createBufferOverflowCheck() {
  return std::make_unique<BufferOverflowCheck>();
}

} // namespace memsafe
