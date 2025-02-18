cmake_minimum_required(VERSION 3.13)
set(PROJECT_NAME "nobs")
project(${PROJECT_NAME})
set(CMAKE_CXX_STANDARD 14)

set(SOURCE_FILES main.c cbuild.h)
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

#add_executable(array array.c)
