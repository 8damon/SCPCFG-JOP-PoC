cmake_minimum_required(VERSION 3.16)

project(SCP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set_source_files_properties(example.c PROPERTIES LANGUAGE CXX)

add_executable(SCP
    example.cpp
    SCP.cpp
)

target_include_directories(SCP PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

if (WIN32)
    target_link_libraries(SCP PRIVATE Psapi)
    target_compile_definitions(SCP PRIVATE UNICODE _UNICODE)
endif()

if (MSVC)
    target_compile_options(SCP PRIVATE /W4 /permissive-)
else()
    target_compile_options(SCP PRIVATE -Wall -Wextra -Wpedantic)
endif()