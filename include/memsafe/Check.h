#pragma once

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/Basic/Diagnostic.h>
#include <clang/Basic/SourceLocation.h>
#include <clang/Basic/SourceManager.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

namespace memsafe {

struct CheckOptions {
  // Empty set means all checks are enabled.
  std::set<std::string> enabledChecks;
  bool failOnWarning = false;
  bool jsonOutput = false;

  bool isCheckEnabled(const std::string &name) const {
    return enabledChecks.empty() || enabledChecks.count(name) > 0;
  }
};

struct Finding {
  std::string file;
  unsigned line = 0;
  unsigned column = 0;
  std::string checkName;
  std::string cwe;
  std::string severity;
  std::string message;
};

class DiagnosticReporter {
public:
  DiagnosticReporter(clang::DiagnosticsEngine &diags,
                     const clang::SourceManager &sm,
                     const CheckOptions &options);

  void report(clang::SourceLocation loc,
              const std::string &checkName,
              const std::string &cwe,
              const std::string &message);

  const std::vector<Finding> &findings() const { return findings_; }
  bool hasFindings() const { return !findings_.empty(); }

private:
  clang::DiagnosticsEngine &diags_;
  const clang::SourceManager &sm_;
  const CheckOptions &options_;
  std::vector<Finding> findings_;
};

class MemorySafetyCheck {
public:
  virtual ~MemorySafetyCheck() = default;
  virtual std::string name() const = 0;
  virtual void run(clang::ASTContext &ctx, DiagnosticReporter &reporter) = 0;
};

std::vector<std::unique_ptr<MemorySafetyCheck>> createAllChecks();

void parseChecksList(const std::string &csv, std::set<std::string> &out);
std::string formatFindingsAsJson(std::vector<Finding> findings);

class MemSafeASTConsumer : public clang::ASTConsumer {
public:
  MemSafeASTConsumer(const CheckOptions &options,
                     std::vector<Finding> *collectedFindings = nullptr);

  void HandleTranslationUnit(clang::ASTContext &ctx) override;

private:
  CheckOptions options_;
  std::vector<Finding> *collectedFindings_;
};

} // namespace memsafe
