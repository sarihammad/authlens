cmake_minimum_required(VERSION 3.20)
project(authlens_analyzer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(authlens main.cpp)
target_include_directories(authlens PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
