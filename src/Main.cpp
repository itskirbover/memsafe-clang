#include "memsafe/Check.h"

#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>

#include <memory>
#include <vector>

namespace {

llvm::cl::OptionCategory MemSafeCategory("memsafe-check options");

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

  clang::tooling::CommonOptionsParser &optionsParser = expectedParser.get();
  clang::tooling::ClangTool tool(optionsParser.getCompilations(),
                                 optionsParser.getSourcePathList());

#ifdef MEMSAFE_CLANG_RESOURCE_DIR
  tool.appendArgumentsAdjuster(clang::tooling::getInsertArgumentAdjuster(
      {"-resource-dir", MEMSAFE_CLANG_RESOURCE_DIR},
      clang::tooling::ArgumentInsertPosition::END));
#endif

  memsafe::CheckOptions options;
  std::vector<memsafe::Finding> findings;
  MemSafeActionFactory factory(options, findings);

  int rc = tool.run(&factory);
  if (rc != 0) {
    return rc;
  }
  return (options.failOnWarning && !findings.empty()) ? 1 : 0;
}
