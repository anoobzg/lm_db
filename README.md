# test_template2
A C++ project template with cmake_tools submodule (cloned from cpp_template)

## Setup

1. Clone the repository:
```bash
git clone https://github.com/anoobzg/test_template2.git
cd test_template2
```

2. Initialize and update submodules:
```bash
git submodule init
git submodule update
```

Or use the combined command:
```bash
git submodule update --init --recursive
```

## Build

Use CMake presets for building:

```bash
# Configure
cmake --preset ninja-debug

# Build
cmake --build out/ninja-debug/build/
```

## Dependencies

This project uses Conan for dependency management. Make sure you have Conan installed:

```bash
pip install conan
```
