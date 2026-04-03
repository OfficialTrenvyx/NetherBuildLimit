cmake_minimum_required(VERSION 3.22.1)
project(NetherBuildLimit)

set(CMAKE_CXX_STANDARD 20)

add_library(NetherBuildLimit SHARED
    src/NetherBuildLimit.cpp
)

target_include_directories(NetherBuildLimit PRIVATE
    include/pl
)

find_library(LOG_LIB log)

target_link_libraries(NetherBuildLimit
    ${LOG_LIB}
)

