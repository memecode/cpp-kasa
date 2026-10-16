cmake_minimum_required(VERSION 3.20)
project(cpp-kasa)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(Threads REQUIRED)

set(LGI_LIB_ONLY TRUE)
add_subdirectory(../lgi/trunk lgi)

# main library:
add_library(cpp-kasa
    src/cpp-kasa.cpp
    src/smart.cpp
    ${LGI_DIR}/src/common/Net/Http.cpp
    ${LGI_DIR}/src/common/Net/OpenSSLSocket.cpp)

target_include_directories(cpp-kasa 
    PUBLIC
        include)
    
target_link_libraries(cpp-kasa
    PUBLIC
        lgi
    PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        Threads::Threads)

# utility executable:
add_executable(util
    src/util.cpp)

target_link_libraries(util
    PRIVATE
        cpp-kasa)

include(CTest)

if(BUILD_TESTING AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(async-tests tests/async.cpp)
    target_link_libraries(async-tests PRIVATE cpp-kasa Threads::Threads OpenSSL::Crypto)
    add_test(NAME async-api COMMAND async-tests)
    set_tests_properties(async-api PROPERTIES TIMEOUT 30)
endif()


# GUI executable:
add_executable(kasa-gui
    src/gui.cpp
    ${LGI_DIR}/src/common/Lgi/LgiMain.cpp
    ${LGI_DIR}/src/common/Text/XmlTreeUi.cpp)

target_link_libraries(kasa-gui
    PRIVATE
        cpp-kasa)