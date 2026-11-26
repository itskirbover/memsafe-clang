#pragma once

#include "memsafe/Check.h"

#include <memory>

namespace memsafe {

std::unique_ptr<MemorySafetyCheck> createBufferOverflowCheck();

} // namespace memsafe
