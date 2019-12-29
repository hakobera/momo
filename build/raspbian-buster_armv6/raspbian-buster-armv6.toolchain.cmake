set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_SYSROOT /root/rootfs)

#set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")

set(triple arm-linux-gnueabihf)
set(CLANG_ROOT /root/llvm/clang)

# specify the cross compiler
set(CMAKE_C_COMPILER ${CLANG_ROOT}/bin/clang)
set(CMAKE_C_COMPILER_TARGET ${triple})
set(CMAKE_CXX_COMPILER ${CLANG_ROOT}/bin/clang++)
set(CMAKE_CXX_COMPILER_TARGET ${triple})

set(ARCH_OPTS "-mfloat-abi=hard -mcpu=arm1176jzf-s -mfpu=vfp")
set(LINKER_OPTS "-v ${ARCH_TARGET} -L/root/rootfs/usr/lib/arm-linux-gnueabihf")

# where is the target environment
set(CMAKE_FIND_ROOT_PATH /root/aws-sdk-cpp)

# search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_C_FLAGS "\
 -isystem /root/rootfs/usr/include/arm-linux-gnueabihf \
 -I /root/rootfs/usr/include \
 -pthread \
 ${ARCH_OPTS}"
  CACHE STRING "C_FLAGS" FORCE)

set(CMAKE_CXX_FLAGS "\
 -D_LIBCPP_ABI_UNSTABLE \
 -nostdinc++ \
 -isystem /root/llvm/libcxx/include \
 -isystem /root/rootfs/usr/include/arm-linux-gnueabihf \
 -I /root/rootfs/usr/include \
 -pthread \
 ${ARCH_OPTS}"
  CACHE STRING "CXX_FLAGS" FORCE)

set(CMAKE_EXE_LINKER_FLAGS "\
 -L /root/rootfs/usr/lib/arm-linux-gnueabihf \
 -L /root/rootfs/usr/lib \
 -L /root/llvm/libcxx/lib \
 -static-libgcc \
 -static-libstdc++ \
 -lpthread"
  CACHE STRING "LINKER FLAGS" FORCE)

set(THREADS_PTHREAD_ARG "0" CACHE STRING "Result from TRY_RUN" FORCE)
#set(CMAKE_CXX_FLAGS_RELEASE "-Ofast -g0 -DNDEBUG" CACHE STRING "C++ Release Flags" FORCE)
