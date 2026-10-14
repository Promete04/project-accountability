add_definitions(-DENABLE_DOCTEST_IN_LIBRARY)
include(FetchContent)

FetchContent_Declare(
    DocTest
    GIT_REPOSITORY "https://github.com/doctest/doctest"
    GIT_TAG        "v2.4.11"
)

FetchContent_GetProperties(DocTest)
if(NOT doctest_POPULATED)
    FetchContent_Populate(DocTest)
endif()

# doctest is header-only. Create a plain INTERFACE target so that
# target_link_libraries(...doctest) only adds the include path — no .a/.dylib.
if(NOT TARGET doctest)
    add_library(doctest INTERFACE)
    target_include_directories(doctest INTERFACE "${doctest_SOURCE_DIR}")
endif()
