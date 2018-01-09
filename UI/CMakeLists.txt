cmake_minimum_required(VERSION 3.6)
project(UI)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp User.cpp)
add_executable(UI ${SOURCE_FILES})
target_link_libraries(UI -lboost_system)