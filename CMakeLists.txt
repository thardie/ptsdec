cmake_minimum_required(VERSION 3.28)
project(tsdec C)

set(CMAKE_C_STANDARD 11)

add_executable(tsdec
        ptsdec.c)

target_link_libraries(tsdec -ldvbcsa -latomic)
