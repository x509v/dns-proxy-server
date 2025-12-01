cmake_minimum_required(VERSION 4.0)
project(dns_new C)

set(CMAKE_C_STANDARD 17)

add_executable(dns_new
        src/main.c
        src/server.c
        include/config_parser.h
        src/config_parser.c
)

target_include_directories(dns_new
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link with json-c
target_link_libraries(dns_new
        ${CMAKE_SOURCE_DIR}/libs/libjson-c.a
)