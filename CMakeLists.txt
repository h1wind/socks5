# CMakeLists.txt

cmake_minimum_required(VERSION 3.16)
project(socks5 VERSION 0.1.0 LANGUAGES C)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE MinSizeRel)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

add_subdirectory(deps)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wconversion")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wimplicit-int")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wwrite-strings")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic")
endif()

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3 /WX /utf-8")
endif()

set(sources
    src/debug.h
    src/main.c
    src/queue.h
    src/socks5.h
    src/socks5.c
)

set(defines PROJECT_VERSION="${PROJECT_VERSION}")
set(libraries event)

set(includes
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/libevent/include
    ${CMAKE_CURRENT_BINARY_DIR}/deps/libevent/include
)

if(WIN32)
    list(APPEND libraries iphlpapi ws2_32)
endif()

add_executable(socks5 ${sources})
target_include_directories(socks5 PRIVATE ${includes})
target_compile_definitions(socks5 PRIVATE ${defines})
target_link_libraries(socks5 PRIVATE ${libraries})
