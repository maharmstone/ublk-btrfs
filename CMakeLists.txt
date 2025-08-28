cmake_minimum_required(VERSION 3.28)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(ublk-check)

include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)

pkg_check_modules(UBLKSRV REQUIRED IMPORTED_TARGET ublksrv)

add_executable(ublk-check src/ublk-check.cpp)

target_sources(ublk-check PUBLIC FILE_SET CXX_MODULES FILES
    src/formatted_error.cpp)

target_compile_options(ublk-check PUBLIC -Wall -Wextra -Wno-unqualified-std-cast-call -Wno-missing-field-initializers)

target_link_libraries(ublk-check PkgConfig::UBLKSRV)

install(TARGETS ublk-check DESTINATION ${CMAKE_INSTALL_BINDIR}
    CXX_MODULES_BMI EXCLUDE_FROM_ALL
)
