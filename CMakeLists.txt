cmake_minimum_required(VERSION 3.10)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# project details
project(AuthApp VERSION 1.0)

set(CMAKE_EXPORT_COMPPILE_COMMANDS ON)

set(USER_EXEC_NAME auth_user)
set(SERVER_EXEC_NAME auth_server)
set(ESCROW_EXEC_NAME escrow)
set(LIBRARY_NAME auth_app_lib)
set(LIBRARY_NAME_SHARED auth_app_lib_shared)
set(LIBRARY_NAME_TA auth_app_lib_ta)

# turn on gdb
set(CMAKE_BUILD_TYPE Debug)

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
include(Cryptopp)
include(CTest)
include(Doctest)
include(Documentation)
include(Warnings)
include(Curses)
include(Sqlite3)
include(FTXUI)

# add shared libraries
set(SOURCES_SHARED
  src-shared/config.cxx
  src-shared/messages.cxx
  src-shared/logger.cxx
  src-shared/util.cxx
  src-shared/keyloaders.cxx)
add_library(${LIBRARY_NAME_SHARED} ${SOURCES_SHARED})
target_include_directories(${LIBRARY_NAME_SHARED} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PUBLIC doctest)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE sqlite3)
target_link_libraries(${LIBRARY_NAME_SHARED} PUBLIC Boost::thread Boost::filesystem Boost::log Boost::log_setup)

# add student libraries
set(SOURCES
  src/pkg/server.cxx
  src/pkg/user.cxx
  src/pkg/vote.cxx
  src/pkg/escrow.cxx
  src/drivers/cli_driver.cxx
  src/drivers/crypto_driver.cxx
  src/drivers/db_driver.cxx
  src/drivers/network_driver.cxx
  src/drivers/repl_driver.cxx
  src/drivers/tui/tui_driver.cpp)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_SHARED} ftxui::screen ftxui::dom ftxui::component ${CURSES_LIBRARIES})

# add user executables
add_executable(${USER_EXEC_NAME} src/cmd/user.cxx)
target_link_libraries(${USER_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# add server executables
add_executable(${SERVER_EXEC_NAME} src/cmd/server.cxx)
target_link_libraries(${SERVER_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# add escrow executable
add_executable(${ESCROW_EXEC_NAME} src/cmd/escrow.cxx)
target_link_libraries(${ESCROW_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# properties
set_target_properties(
  ${LIBRARY_NAME_SHARED}
  ${LIBRARY_NAME}
  ${USER_EXEC_NAME}
  ${SERVER_EXEC_NAME}
  ${ESCROW_EXEC_NAME}
    PROPERTIES
      CXX_STANDARD 20
      CXX_STANDARD_REQUIRED YES
      CXX_EXTENSIONS YES
)

# add tests
add_subdirectory(test)
add_custom_target(check COMMAND ./test.sh WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
