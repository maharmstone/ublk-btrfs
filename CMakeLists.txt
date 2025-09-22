cmake_minimum_required(VERSION 3.28)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(ublk-btrfs)

include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)

pkg_check_modules(UBLKSRV REQUIRED IMPORTED_TARGET ublksrv)

add_executable(ublk-btrfs src/ublk-btrfs.cpp)

target_sources(ublk-btrfs PUBLIC FILE_SET CXX_MODULES FILES
    src/formatted_error.cpp
    src/mmap.cpp
    src/cxxbtrfs.cpp)

target_compile_options(ublk-btrfs PUBLIC -Wall -Wextra -Wno-unqualified-std-cast-call -Wno-missing-field-initializers)

target_link_libraries(ublk-btrfs PkgConfig::UBLKSRV)

install(TARGETS ublk-btrfs DESTINATION ${CMAKE_INSTALL_BINDIR}
    CXX_MODULES_BMI EXCLUDE_FROM_ALL
)
