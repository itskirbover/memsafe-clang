# memsafe-clang

A lightweight Clang AST plugin (`libMemSafePlugin.so`) and standalone pre-compilation static analyzer CLI (`memsafe-check`) that detects common C/C++ memory-safety bugs **before compilation**:

- **Buffer Overflows** (`buffer-overflow` — CWE-120 / CWE-787): constant out-of-bounds array indexing, `memcpy`/`memmove`/`memset`/`strncpy` size overflows against static arrays, and unsafe unbounded C string APIs (`gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`).
- **Use-After-Free & Double-Free** (`use-after-free` — CWE-416 / CWE-415): intraprocedural CFG-based tracking of `free`, `delete`, and `delete[]` followed by dereference, subscript, member access, function-argument pass, or duplicate deallocation.
- **Uninitialized Pointers** (`uninitialized-pointer` — CWE-457 / CWE-824): intraprocedural CFG-based tracking of uninitialized local pointer declarations dereferenced prior to assignment or out-parameter initialization.

## Requirements

- CMake >= 3.20
- Ninja or Make
- LLVM & Clang development packages (`libLLVM`, `libclang-cpp`, Clang/LLVM CMake configs)
- C++20 compiler (`clang++` or `g++`)

## Building

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Usage

### Standalone CLI (`memsafe-check`)

```bash
# Run all checks with Clang-native diagnostics
./build/memsafe-check path/to/file.cpp -- -std=c++20

# Filter specific checks and fail on warnings
./build/memsafe-check --checks=buffer-overflow,use-after-free --fail-on-warning file.c --

# Machine-readable JSON output for CI
./build/memsafe-check --format=json file.c --
```

### Clang Compiler Plugin (`libMemSafePlugin.so`)

```bash
# Emit warnings during compilation
clang++ -fplugin=./build/libMemSafePlugin.so -fsyntax-only file.cpp

# Block compilation on any memory-safety finding
clang++ -fplugin=./build/libMemSafePlugin.so \
  -Xclang -plugin-arg-memsafe -Xclang -fail-on-warning \
  -fsyntax-only file.cpp
```

## License

MIT — see [LICENSE](LICENSE).
