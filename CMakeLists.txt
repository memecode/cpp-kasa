cmake_minimum_required(VERSION 3.20)
project(cpp-kasa)

set(CMAKE_CXX_STANDARD 17)

set(LGI_LIB_ONLY TRUE)
add_subdirectory(../lgi/trunk lgi)

# main library:
add_library(cpp-kasa
    src/cpp-kasa.cpp)

target_include_directories(cpp-kasa 
    PUBLIC
        include)
    
target_link_libraries(cpp-kasa
    PUBLIC
        lgi)

# utility executable:
add_executable(util
    src/util.cpp)

target_link_libraries(util
    PRIVATE
        cpp-kasa)