cmake_minimum_required(VERSION 3.20)
project(awaos_winss C)
set(CMAKE_C_STANDARD 11)

# Build subdirectories
add_subdirectory(winss/loader)
add_subdirectory(winss/ntshim32)
