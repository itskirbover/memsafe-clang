#include "memsafe/Check.h"

#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendPluginRegistry.h>

#include <memory>
#include <string>
#include <vector>

namespace {

class MemSafePluginAction : public clang::PluginASTAction {
public:
  std::unique_ptr<clang::ASTConsumer>
  CreateASTConsumer(clang::CompilerInstance &, llvm::StringRef) override {
    return std::make_unique<memsafe::MemSafeASTConsumer>(options_);
  }

  bool ParseArgs(const clang::CompilerInstance &,
                 const std::vector<std::string> &args) override {
    for (const auto &arg : args) {
      if (arg == "-fail-on-warning" || arg == "fail-on-warning") {
        options_.failOnWarning = true;
      }
    }
    return true;
  }

  ActionType getActionType() override { return AddBeforeMainAction; }

private:
  memsafe::CheckOptions options_;
};

} // namespace

static clang::FrontendPluginRegistry::Add<MemSafePluginAction>
    X("memsafe", "Flag common C/C++ memory-safety bugs before compilation");
