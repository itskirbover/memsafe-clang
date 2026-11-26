#include "memsafe/Check.h"
#include "memsafe/Checks.h"

#include <clang/Basic/SourceManager.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <sstream>
#include <tuple>

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
  checks.push_back(createBufferOverflowCheck());
  checks.push_back(createUseAfterFreeCheck());
  checks.push_back(createUninitializedPointerCheck());
  return checks;
}

void parseChecksList(const std::string &csv, std::set<std::string> &out) {
  out.clear();
  if (csv.empty() || csv == "all" || csv == "*") {
    return;
  }
  std::stringstream ss(csv);
  std::string item;
  while (std::getline(ss, item, ',')) {
    auto first = item.find_first_not_of(" \t");
    if (first == std::string::npos) {
      continue;
    }
    auto last = item.find_last_not_of(" \t");
    std::string trimmed = item.substr(first, last - first + 1);
    if (trimmed == "all" || trimmed == "*") {
      out.clear();
      return;
    }
    out.insert(trimmed);
  }
}

std::string formatFindingsAsJson(std::vector<Finding> findings) {
  std::sort(findings.begin(), findings.end(),
            [](const Finding &a, const Finding &b) {
              return std::tie(a.file, a.line, a.column, a.checkName, a.message) <
                     std::tie(b.file, b.line, b.column, b.checkName, b.message);
            });

  llvm::json::Array arr;
  for (const Finding &f : findings) {
    llvm::json::Object obj;
    obj["file"] = f.file;
    obj["line"] = static_cast<int64_t>(f.line);
    obj["column"] = static_cast<int64_t>(f.column);
    obj["check"] = f.checkName;
    obj["cwe"] = f.cwe;
    obj["severity"] = f.severity;
    obj["message"] = f.message;
    arr.push_back(std::move(obj));
  }

  llvm::json::Object root;
  root["tool"] = "memsafe-clang";
  root["count"] = static_cast<int64_t>(findings.size());
  root["findings"] = std::move(arr);

  std::string out;
  llvm::raw_string_ostream os(out);
  os << llvm::formatv("{0:2}\n", llvm::json::Value(std::move(root)));
  return out;
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
