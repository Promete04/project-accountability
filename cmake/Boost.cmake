set(Boost_NO_WARN_NEW_VERSIONS ON)
find_package(Boost 1.71 REQUIRED COMPONENTS thread filesystem log log_setup)
include_directories(${Boost_INCLUDE_DIR})
