cmake_minimum_required(VERSION 3.11)

project(GB28181)

add_subdirectory(3rdparty/JThread)
add_subdirectory(3rdparty/JRTPLIB)
add_subdirectory(3rdparty/mxml)


file(GLOB gb28181_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/osipservice.cpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/src/filenameio.cpp)

add_executable(gbexecer ${gb28181_SRC})

target_include_directories(gbexecer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/JRTPLIB/src)
target_include_directories(gbexecer PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/JRTPLIB/src)
target_include_directories(gbexecer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/mxml)
target_link_libraries(gbexecer PRIVATE jrtplib mxml)