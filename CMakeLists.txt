cmake_minimum_required(VERSION 3.11)

project(GB28181)

add_subdirectory(3rdparty/JThread)
add_subdirectory(3rdparty/JRTPLIB)
add_subdirectory(3rdparty/mxml)
add_subdirectory(3rdparty/osip)
add_subdirectory(3rdparty/exosip)
add_subdirectory(3rdparty/c-ares)


file(GLOB gb28181_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/osipservice.cpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/src/filenameio.cpp)

add_executable(gbexecer ${gb28181_SRC})

target_include_directories(gbexecer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/JRTPLIB/src)
target_include_directories(gbexecer PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/JRTPLIB/src)
target_include_directories(gbexecer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/mxml)

include_directories(${CMAKE_SOURCE_DIR}/3rdparty/exosip/include)
include_directories(${CMAKE_SOURCE_DIR}/3rdparty/osip/include)

if(MSVC)
#debug default
target_link_directories(gbexecer PRIVATE ${CMAKE_BINARY_DIR}/3rdparty/JRTPLIB/src/Debug)
# target_link_directories(gbexecer PRIVATE ${CMAKE_BINARY_DIR}/3rdparty/osip/Debug)
# target_link_directories(gbexecer PRIVATE ${CMAKE_BINARY_DIR}/3rdparty/mxml/Debug)
# make all lib static
target_link_libraries(gbexecer PRIVATE jrtplib_d mxml1 exosip osip osipparser)
else()
target_link_libraries(gbexecer PRIVATE jrtplib mxml1 exosip osip osipparser)
endif()