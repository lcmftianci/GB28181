cmake_minimum_required(VERSION 3.11)

project(mxml)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/vcnet)

file(GLOB mxml_SRC ${CMAKE_CURRENT_SOURCE_DIR}/mxml-attr.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/mxml-entity.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/mxml-file.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/mxml-get.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/mxml-index.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/mxml-node.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/mxml-private.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/mxml-search.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/mxml-set.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/mxml-string.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/vcnet/mxml1.def)

add_library(mxml SHARED ${mxml_SRC})
target_include_directories(mxml PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/)