#pragma once

#include "memsafe/Check.h"

#include <memory>

namespace memsafe {

std::unique_ptr<MemorySafetyCheck> createBufferOverflowCheck();
std::unique_ptr<MemorySafetyCheck> createUseAfterFreeCheck();

} // namespace memsafe
