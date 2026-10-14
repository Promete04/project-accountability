include(FetchContent)

FetchContent_Declare(
  SEAL
  GIT_REPOSITORY https://github.com/microsoft/SEAL.git
  GIT_TAG v4.1.1
)

set(SEAL_BUILD_TESTS OFF CACHE BOOL "Build SEAL tests" FORCE)
set(SEAL_BUILD_EXAMPLES OFF CACHE BOOL "Build SEAL examples" FORCE)
set(SEAL_USE_ZLIB OFF CACHE BOOL "Use ZLIB" FORCE)
set(SEAL_USE_ZSTD OFF CACHE BOOL "Use ZSTD" FORCE)
set(SEAL_USE_MSGSL OFF CACHE BOOL "Use MSGSL" FORCE)

FetchContent_MakeAvailable(SEAL)
