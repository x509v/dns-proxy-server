cmake_minimum_required(VERSION 3.10)

message(STATUS "CMAKE_SOURCE_DIR is: ${CMAKE_SOURCE_DIR}")
project(dns C)


set(CMAKE_C_STANDARD 11)

# Find json-c library
find_package(json-c REQUIRED)
# Add source files
add_executable(dns
        main.c
        config_parser.c
        server.c
)

# Link with json-c
target_link_libraries(dns
        ${CMAKE_SOURCE_DIR}/libs/libjson-c.a
)