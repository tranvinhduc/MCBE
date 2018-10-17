cmake_minimum_required(VERSION 3.10)
project(MCBEv0 C)

set(CMAKE_C_STANDARD 99)
include_directories("/usr/local/include/pbc")
link_directories("/usr/local/lib")

add_executable(MCBEv0 main.c fix.h mcbe.h types.h types.c
        esp.c esp.h
        mcbe.c readfile.c readfile.h)
target_link_libraries(MCBEv0 pbc gmp)