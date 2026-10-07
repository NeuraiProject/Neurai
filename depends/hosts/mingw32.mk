mingw32_CFLAGS=-pipe
mingw32_CXXFLAGS=$(mingw32_CFLAGS)

mingw32_release_CFLAGS=-O2
mingw32_release_CXXFLAGS=$(mingw32_release_CFLAGS)

mingw32_debug_CFLAGS=-O1
mingw32_debug_CXXFLAGS=$(mingw32_debug_CFLAGS)

mingw32_debug_CPPFLAGS=-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC

# Read as $(host_os)_cmake_system by the $(package)_cmake macro (funcs.mk), and
# host_os is "mingw32": named mingw_cmake_system, CMake builds got no
# CMAKE_SYSTEM_NAME and configured for Linux.
mingw32_cmake_system=Windows
