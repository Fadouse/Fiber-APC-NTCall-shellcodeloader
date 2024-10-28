cmake_minimum_required(VERSION 3.29)
project(fiberAPCNTshellcodeloader)


set(CMAKE_EXE_LINKER_FLAGS "-static")
set(CMAKE_CXX_STANDARD 20)

add_executable(fiberAPCNTshellcodeloader main.cpp)
