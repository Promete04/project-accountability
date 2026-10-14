include(FetchContent)

# 1. Try pkg-config first (works on NixOS, Debian/Ubuntu with libcryptopp-dev).
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(CRYPTOPP_PKG QUIET cryptopp)
endif()

if(CRYPTOPP_PKG_FOUND)
    message(STATUS "Found cryptopp via pkg-config: ${CRYPTOPP_PKG_LINK_LIBRARIES}")

    include_directories(${CRYPTOPP_PKG_INCLUDE_DIRS})

    add_library(cryptopp INTERFACE)
    target_include_directories(cryptopp INTERFACE ${CRYPTOPP_PKG_INCLUDE_DIRS})
    target_link_libraries(cryptopp INTERFACE ${CRYPTOPP_PKG_LINK_LIBRARIES})
    target_link_directories(cryptopp INTERFACE ${CRYPTOPP_PKG_LIBRARY_DIRS})
else()
    # 2. Try find_library for macOS Homebrew and standard Linux paths.
    find_library(CRYPTOPP_LIBRARY
        NAMES cryptopp
        HINTS
            /opt/homebrew/opt/cryptopp/lib
            /usr/local/opt/cryptopp/lib
            /usr/lib /usr/local/lib
    )
    find_path(CRYPTOPP_INCLUDE_DIR
        NAMES cryptlib.h
        HINTS
            /opt/homebrew/opt/cryptopp/include/cryptopp
            /usr/local/opt/cryptopp/include/cryptopp
            /usr/include/cryptopp
            /usr/local/include/cryptopp
    )

    if(CRYPTOPP_LIBRARY AND CRYPTOPP_INCLUDE_DIR)
        message(STATUS "Found system cryptopp: ${CRYPTOPP_LIBRARY}")
        message(STATUS "cryptopp include dir: ${CRYPTOPP_INCLUDE_DIR}")

        get_filename_component(CRYPTOPP_INCLUDE_PARENT "${CRYPTOPP_INCLUDE_DIR}" DIRECTORY)

        set(CRYPTOPP_COMPAT_DIR "${CMAKE_BINARY_DIR}/cryptopp-compat")
        file(MAKE_DIRECTORY "${CRYPTOPP_COMPAT_DIR}")
        if(NOT EXISTS "${CRYPTOPP_COMPAT_DIR}/crypto++")
            file(CREATE_LINK "${CRYPTOPP_INCLUDE_DIR}" "${CRYPTOPP_COMPAT_DIR}/crypto++" SYMBOLIC)
        endif()

        include_directories("${CRYPTOPP_INCLUDE_PARENT}" "${CRYPTOPP_COMPAT_DIR}")

        add_library(cryptopp STATIC IMPORTED GLOBAL)
        set_target_properties(cryptopp PROPERTIES
            IMPORTED_LOCATION "${CRYPTOPP_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${CRYPTOPP_INCLUDE_PARENT};${CRYPTOPP_COMPAT_DIR}"
        )
    else()
        # 3. Fall back to building from source (8.9.0).
        message(STATUS "System cryptopp not found — fetching 8.9.0 from source")

        set(CRYPTOPP_CMAKE_TAG "CRYPTOPP_8_9_0")

        FetchContent_Declare(cryptopp-cmake
            GIT_REPOSITORY https://github.com/noloader/cryptopp-cmake
            GIT_TAG        ${CRYPTOPP_CMAKE_TAG}
        )
        FetchContent_Declare(cryptopp
            GIT_REPOSITORY https://github.com/weidai11/cryptopp
            GIT_TAG        ${CRYPTOPP_CMAKE_TAG}
        )

        FetchContent_GetProperties(cryptopp-cmake)
        if(NOT cryptopp-cmake_POPULATED)
            FetchContent_Populate(cryptopp-cmake)
        endif()

        FetchContent_GetProperties(cryptopp)
        if(NOT cryptopp_POPULATED)
            FetchContent_Populate(cryptopp)
            file(COPY ${cryptopp-cmake_SOURCE_DIR}/CMakeLists.txt
                 DESTINATION ${cryptopp_SOURCE_DIR})
            set(DISABLE_ASM ON CACHE BOOL "" FORCE)
            set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
            set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "" FORCE)
            add_subdirectory(${cryptopp_SOURCE_DIR} ${cryptopp_BINARY_DIR})
        endif()

        set(CRYPTOPP_COMPAT_DIR "${CMAKE_BINARY_DIR}/cryptopp-compat")
        file(MAKE_DIRECTORY "${CRYPTOPP_COMPAT_DIR}")
        if(NOT EXISTS "${CRYPTOPP_COMPAT_DIR}/crypto++")
            file(CREATE_LINK "${cryptopp_SOURCE_DIR}" "${CRYPTOPP_COMPAT_DIR}/crypto++" SYMBOLIC)
        endif()

        include_directories("${cryptopp_SOURCE_DIR}/.." "${CRYPTOPP_COMPAT_DIR}")
    endif()
endif()
