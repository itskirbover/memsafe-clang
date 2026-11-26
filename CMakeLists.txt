cmake_minimum_required(VERSION 3.20)
project(memsafe-clang VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION} (${LLVM_DIR})")
message(STATUS "Found Clang (${Clang_DIR})")

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# Resolve LLVM and Clang link libraries across shared (Arch/Debian) and static builds
if(TARGET clang-cpp)
  set(MEMSAFE_CLANG_LIBS clang-cpp)
else()
  set(MEMSAFE_CLANG_LIBS
    clangTooling
    clangFrontend
    clangSerialization
    clangDriver
    clangParse
    clangSema
    clangAnalysis
    clangAST
    clangASTMatchers
    clangBasic
    clangEdit
    clangLex
  )
endif()

if(TARGET LLVM)
  set(MEMSAFE_LLVM_LIBS LLVM)
else()
  llvm_map_components_to_libnames(MEMSAFE_LLVM_LIBS support core option)
endif()

# Detect Clang resource directory so standalone memsafe-check finds stddef.h/stdarg.h
execute_process(
  COMMAND ${CMAKE_CXX_COMPILER} -print-resource-dir
  OUTPUT_VARIABLE MEMSAFE_CLANG_RESOURCE_DIR
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
if(MEMSAFE_CLANG_RESOURCE_DIR)
  message(STATUS "Clang resource dir: ${MEMSAFE_CLANG_RESOURCE_DIR}")
  add_compile_definitions(MEMSAFE_CLANG_RESOURCE_DIR="${MEMSAFE_CLANG_RESOURCE_DIR}")
endif()

# Core analysis library
add_library(memsafe_core STATIC
  src/Core.cpp
  src/checks/BufferOverflowCheck.cpp
  src/checks/UseAfterFreeCheck.cpp
  src/checks/UninitializedPointerCheck.cpp
)
target_include_directories(memsafe_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(memsafe_core PRIVATE -Wall -Wextra -fno-rtti)
set_target_properties(memsafe_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(memsafe_core PUBLIC ${MEMSAFE_CLANG_LIBS} ${MEMSAFE_LLVM_LIBS})

# Clang AST Compiler Plugin (clang -fplugin=libMemSafePlugin.so)
add_library(MemSafePlugin MODULE
  src/Plugin.cpp
)
target_compile_options(MemSafePlugin PRIVATE -Wall -Wextra -fno-rtti)
target_link_libraries(MemSafePlugin PRIVATE memsafe_core)

# Standalone pre-compilation static analyzer CLI
add_executable(memsafe-check
  src/Main.cpp
)
target_compile_options(memsafe-check PRIVATE -Wall -Wextra -fno-rtti)
target_link_libraries(memsafe-check PRIVATE memsafe_core)

enable_testing()

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
  set(MEMSAFE_TEST_CASES buffer-overflow use-after-free uninit-pointer filtering plugin)
  foreach(CASE ${MEMSAFE_TEST_CASES})
    add_test(
      NAME memsafe_${CASE}
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py
        --cli $<TARGET_FILE:memsafe-check>
        --plugin $<TARGET_FILE:MemSafePlugin>
        --clang ${CMAKE_CXX_COMPILER}
        --fixtures ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures
        --case ${CASE}
    )
  endforeach()
endif()
