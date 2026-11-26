#include "memsafe/Check.h"

#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>

#include <memory>
#include <string>
#include <vector>

namespace {

llvm::cl::OptionCategory MemSafeCategory("memsafe-check options");

llvm::cl::opt<std::string> ChecksOpt(
    "checks",
    llvm::cl::desc(
        "Comma-separated list of checks to run "
        "(buffer-overflow,use-after-free,uninitialized-pointer, or 'all')"),
    llvm::cl::init("all"), llvm::cl::cat(MemSafeCategory));

llvm::cl::opt<bool> FailOnWarningOpt(
    "fail-on-warning",
    llvm::cl::desc(
        "Treat memory-safety findings as errors and exit with non-zero status"),
    llvm::cl::init(false), llvm::cl::cat(MemSafeCategory));

llvm::cl::opt<std::string> FormatOpt(
    "format",
    llvm::cl::desc("Output format: 'text' (Clang diagnostics) or 'json'"),
    llvm::cl::init("text"), llvm::cl::cat(MemSafeCategory));

class MemSafeFrontendAction : public clang::ASTFrontendAction {
public:
  MemSafeFrontendAction(const memsafe::CheckOptions &options,
                        std::vector<memsafe::Finding> &findings)
      : options_(options), findings_(findings) {}

  std::unique_ptr<clang::ASTConsumer>
  CreateASTConsumer(clang::CompilerInstance &, llvm::StringRef) override {
    return std::make_unique<memsafe::MemSafeASTConsumer>(options_, &findings_);
  }

private:
  memsafe::CheckOptions options_;
  std::vector<memsafe::Finding> &findings_;
};

class MemSafeActionFactory : public clang::tooling::FrontendActionFactory {
public:
  MemSafeActionFactory(const memsafe::CheckOptions &options,
                       std::vector<memsafe::Finding> &findings)
      : options_(options), findings_(findings) {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<MemSafeFrontendAction>(options_, findings_);
  }

private:
  memsafe::CheckOptions options_;
  std::vector<memsafe::Finding> &findings_;
};

} // namespace

int main(int argc, const char **argv) {
  auto expectedParser =
      clang::tooling::CommonOptionsParser::create(argc, argv, MemSafeCategory);
  if (!expectedParser) {
    llvm::errs() << expectedParser.takeError();
    return 1;
  }

  if (FormatOpt != "text" && FormatOpt != "json") {
    llvm::errs() << "error: unsupported --format '" << FormatOpt
                 << "' (expected 'text' or 'json')\n";
    return 1;
  }

  memsafe::CheckOptions options;
  memsafe::parseChecksList(ChecksOpt, options.enabledChecks);
  options.failOnWarning = FailOnWarningOpt;
  options.jsonOutput = (FormatOpt == "json");

  clang::tooling::CommonOptionsParser &optionsParser = expectedParser.get();
  clang::tooling::ClangTool tool(optionsParser.getCompilations(),
                                 optionsParser.getSourcePathList());

#ifdef MEMSAFE_CLANG_RESOURCE_DIR
  tool.appendArgumentsAdjuster(clang::tooling::getInsertArgumentAdjuster(
      {"-resource-dir", MEMSAFE_CLANG_RESOURCE_DIR},
      clang::tooling::ArgumentInsertPosition::END));
#endif

  std::vector<memsafe::Finding> findings;
  MemSafeActionFactory factory(options, findings);

  int rc = tool.run(&factory);

  if (options.jsonOutput) {
    llvm::outs() << memsafe::formatFindingsAsJson(findings);
  }

  if (rc != 0) {
    return rc;
  }
  return (options.failOnWarning && !findings.empty()) ? 1 : 0;
}
