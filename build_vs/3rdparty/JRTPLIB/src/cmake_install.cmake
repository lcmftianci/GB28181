# Install script for directory: F:/mygitsource/GB28181/3rdparty/JRTPLIB/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Program Files (x86)/GB28181")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/jrtplib3" TYPE FILE FILES
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcpapppacket.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcpbyepacket.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcpcompoundpacket.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcpcompoundpacketbuilder.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcppacket.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcppacketbuilder.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcprrpacket.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcpscheduler.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcpsdesinfo.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcpsdespacket.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcpsrpacket.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtcpunknownpacket.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpaddress.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpcollisionlist.h"
    "F:/mygitsource/GB28181/build_vs/3rdparty/JRTPLIB/src/rtpconfig.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpdebug.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpdefines.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtperrors.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtphashtable.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpinternalsourcedata.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpipv4address.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpipv4destination.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpipv6address.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpipv6destination.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpkeyhashtable.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtplibraryversion.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpmemorymanager.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpmemoryobject.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtppacket.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtppacketbuilder.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtppollthread.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtprandom.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtprandomrand48.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtprandomrands.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtprandomurandom.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtprawpacket.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpsession.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpsessionparams.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpsessionsources.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpsourcedata.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpsources.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpstructs.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtptimeutilities.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtptransmitter.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtptypes_win.h"
    "F:/mygitsource/GB28181/build_vs/3rdparty/JRTPLIB/src/rtptypes.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpudpv4transmitter.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpudpv6transmitter.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpbyteaddress.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpexternaltransmitter.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpsecuresession.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpsocketutil.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpabortdescriptors.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtpselect.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtptcpaddress.h"
    "F:/mygitsource/GB28181/3rdparty/JRTPLIB/src/rtptcptransmitter.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
     "C:/Program Files (x86)/GB28181/lib/jrtplib_d.lib")
    if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
      message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
    endif()
    if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
      message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
    endif()
    file(INSTALL DESTINATION "C:/Program Files (x86)/GB28181/lib" TYPE STATIC_LIBRARY FILES "F:/mygitsource/GB28181/build_vs/3rdparty/JRTPLIB/src/Debug/jrtplib_d.lib")
  elseif("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
     "C:/Program Files (x86)/GB28181/lib/jrtplib.lib")
    if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
      message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
    endif()
    if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
      message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
    endif()
    file(INSTALL DESTINATION "C:/Program Files (x86)/GB28181/lib" TYPE STATIC_LIBRARY FILES "F:/mygitsource/GB28181/build_vs/3rdparty/JRTPLIB/src/Release/jrtplib.lib")
  elseif("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
    list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
     "C:/Program Files (x86)/GB28181/lib/jrtplib.lib")
    if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
      message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
    endif()
    if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
      message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
    endif()
    file(INSTALL DESTINATION "C:/Program Files (x86)/GB28181/lib" TYPE STATIC_LIBRARY FILES "F:/mygitsource/GB28181/build_vs/3rdparty/JRTPLIB/src/MinSizeRel/jrtplib.lib")
  elseif("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
     "C:/Program Files (x86)/GB28181/lib/jrtplib.lib")
    if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
      message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
    endif()
    if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
      message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
    endif()
    file(INSTALL DESTINATION "C:/Program Files (x86)/GB28181/lib" TYPE STATIC_LIBRARY FILES "F:/mygitsource/GB28181/build_vs/3rdparty/JRTPLIB/src/RelWithDebInfo/jrtplib.lib")
  endif()
endif()

