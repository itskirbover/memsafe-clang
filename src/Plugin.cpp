#include "memsafe/Check.h"

#include <clang/Basic/Diagnostic.h>
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

  bool ParseArgs(const clang::CompilerInstance &ci,
                 const std::vector<std::string> &args) override {
    for (const auto &arg : args) {
      if (arg == "-fail-on-warning" || arg == "fail-on-warning" ||
          arg == "-Werror") {
        options_.failOnWarning = true;
      } else if (arg.rfind("-checks=", 0) == 0) {
        memsafe::parseChecksList(arg.substr(8), options_.enabledChecks);
      } else if (arg.rfind("checks=", 0) == 0) {
        memsafe::parseChecksList(arg.substr(7), options_.enabledChecks);
      } else {
        clang::DiagnosticsEngine &diags = ci.getDiagnostics();
        unsigned id = diags.getCustomDiagID(
            clang::DiagnosticsEngine::Error,
            "unknown memsafe plugin argument '%0'");
        diags.Report(id) << arg;
        return false;
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
