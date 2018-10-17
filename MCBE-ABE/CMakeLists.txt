cmake_minimum_required(VERSION 3.10)
project(MCBE-ABE C)

set(CMAKE_C_STANDARD 99)
include_directories("/usr/local/include/pbc")
link_directories("/usr/local/lib")

add_executable(MCBE-ABE main.c fix.h abe.h abe.c types.h types.c
        esp.c esp.h
        readfile.c readfile.h)
target_link_libraries(MCBE-ABE pbc gmp)