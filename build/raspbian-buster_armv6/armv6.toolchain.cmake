# file name: arm.toolchain.cmake
SET(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# specify the cross compiler
SET(CMAKE_C_COMPILER /root/llvm/clang/bin/clang)
SET(CMAKE_CXX_COMPILER /root/llvm/clang/bin/clang++)

SET(CMAKE_SYSROOT /root/rootfs)
SET(CMAKE_CXX_FLAGS "-v -D_LIBCPP_ABI_UNSTABLE -nostdinc++ -isystem/root/llvm/libcxx/include --target=arm-linux-gnueabihf -I/root/rootfs/usr/include/arm-linux-gnueabihf")
SET(CMAKE_MODULE_LINKER_FLAGS_INIT "-v -L/root/rootfs/usr/lib/arm-linux-gnueabihf")

# where is the target environment
SET(CMAKE_FIND_ROOT_PATH /root/aws-sdk-cpp)

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# for libraries and headers in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)