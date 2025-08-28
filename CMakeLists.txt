cmake_minimum_required(VERSION 3.28)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(ublk-check)

include(GNUInstallDirs)

add_executable(ublk-check src/ublk-check.cpp)

target_compile_options(ublk-check PUBLIC -Wall -Wextra -Wno-unqualified-std-cast-call)

install(TARGETS ublk-check DESTINATION ${CMAKE_INSTALL_BINDIR}
    CXX_MODULES_BMI EXCLUDE_FROM_ALL
)
