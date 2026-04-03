cmake_minimum_required(VERSION 3.22.1)
project(NetherBuildLimit)

set(CMAKE_CXX_STANDARD 20)

add_library(NetherBuildLimit SHARED
    src/NetherBuildLimit.cpp
)

target_include_directories(NetherBuildLimit PRIVATE
    include/pl
)

add_library(GlossHook STATIC IMPORTED)
set_target_properties(GlossHook PROPERTIES
    IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/arm64-v8a/libGlossHook.a
)

find_library(LOG_LIB log)

target_link_libraries(NetherBuildLimit
    GlossHook
    ${LOG_LIB}
)

