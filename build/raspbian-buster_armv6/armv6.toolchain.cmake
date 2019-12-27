# file name: arm.toolchain.cmake
SET(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# specify the cross compiler
SET(CMAKE_C_COMPILER /root/llvm/clang/bin/clang)
SET(CMAKE_CXX_COMPILER /root/llvm/clang/bin/clang++)

# where is the target environment
SET(CMAKE_FIND_ROOT_PATH /root/aws-sdk-cpp)

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)