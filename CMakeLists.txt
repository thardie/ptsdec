cmake_minimum_required(VERSION 3.28)
project(ptsdec C)

set(CMAKE_C_STANDARD 11)

add_executable(ptsdec
        ptsdec.c)

target_link_libraries(ptsdec -ldvbcsa -latomic)
