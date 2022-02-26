cmake_minimum_required(VERSION 3.20)

project(IDALoadIl2CppDumperPlugin CXX)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

find_package(IdaSdk REQUIRED)

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake")
    file(DOWNLOAD "https://raw.githubusercontent.com/akemimadoka/cmake-conan/develop/conan.cmake"
                    "${CMAKE_BINARY_DIR}/conan.cmake" SHOW_PROGRESS
                    STATUS _download_status)
    list(GET _download_status 0 _download_status_code)
    list(GET _download_status 1 _download_status_msg)
    if(NOT _download_status_code EQUAL 0)
        file(REMOVE "${CMAKE_BINARY_DIR}/conan.cmake")
        message(FATAL_ERROR "Failed to download conan.cmake, status code is ${_download_status_code}, msg is ${_download_status_msg}")
    endif()
endif()

include(${CMAKE_BINARY_DIR}/conan.cmake)

conan_cmake_run(CONANFILE conanfile.txt
                BASIC_SETUP CMAKE_TARGETS
                PROFILE_AUTO all
                BUILD missing
                ENV CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER}
)

add_ida_plugin(IDALoadIl2CppDumperPlugin NOEA32 src/Plugin.cpp)
ida_target_link_libraries(IDALoadIl2CppDumperPlugin ${CONAN_TARGETS})
set_ida_target_properties(IDALoadIl2CppDumperPlugin PROPERTIES
    CXX_STANDARD 20
)
if(MSVC)
    set_ida_target_properties(IDALoadIl2CppDumperPlugin PROPERTIES
        COMPILE_OPTIONS /utf-8
    )
endif()
