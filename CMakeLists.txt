cmake_minimum_required(VERSION 3.16 FATAL_ERROR) # Policies <= CMP0097 default to NEW

project(lm_db)

set(BUILD_DEMO 0)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    include(cmake_tools/entry/desktop-cpp.cmake)
    __install_conan_requirements(MSVC_RUNTIME "dynamic")

    set(BUILD_DEMO 1)
endif()

add_subdirectory(src)

if(BUILD_DEMO)
    add_subdirectory(demo)
endif()

