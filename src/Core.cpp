#include "memsafe/Check.h"

#include <clang/Basic/SourceManager.h>

namespace memsafe {

DiagnosticReporter::DiagnosticReporter(clang::DiagnosticsEngine &diags,
                                       const clang::SourceManager &sm,
                                       const CheckOptions &options)
    : diags_(diags), sm_(sm), options_(options) {}

void DiagnosticReporter::report(clang::SourceLocation loc,
                                const std::string &checkName,
                                const std::string &cwe,
                                const std::string &message) {
  clang::SourceLocation spellingLoc = sm_.getSpellingLoc(loc);
  clang::PresumedLoc presumed = sm_.getPresumedLoc(spellingLoc);

  Finding f;
  if (presumed.isValid()) {
    f.file = presumed.getFilename();
    f.line = presumed.getLine();
    f.column = presumed.getColumn();
  }
  f.checkName = checkName;
  f.cwe = cwe;
  f.severity = options_.failOnWarning ? "error" : "warning";
  f.message = message;
  findings_.push_back(f);

  if (!options_.jsonOutput) {
    auto level = options_.failOnWarning ? clang::DiagnosticsEngine::Error
                                        : clang::DiagnosticsEngine::Warning;
    unsigned diagId =
        diags_.getCustomDiagID(level, "[memsafe:%0] %1 [%2]");
    diags_.Report(spellingLoc, diagId) << checkName << message << cwe;
  }
}

std::vector<std::unique_ptr<MemorySafetyCheck>> createAllChecks() {
  std::vector<std::unique_ptr<MemorySafetyCheck>> checks;
  // Individual checks are registered here as they are implemented.
  return checks;
}

MemSafeASTConsumer::MemSafeASTConsumer(const CheckOptions &options,
                                       std::vector<Finding> *collectedFindings)
    : options_(options), collectedFindings_(collectedFindings) {}

void MemSafeASTConsumer::HandleTranslationUnit(clang::ASTContext &ctx) {
  DiagnosticReporter reporter(ctx.getDiagnostics(), ctx.getSourceManager(),
                              options_);
  auto checks = createAllChecks();
  for (auto &check : checks) {
    if (options_.isCheckEnabled(check->name())) {
      check->run(ctx, reporter);
    }
  }
  if (collectedFindings_) {
    const auto &found = reporter.findings();
    collectedFindings_->insert(collectedFindings_->end(), found.begin(),
                               found.end());
  }
}

} // namespace memsafe
