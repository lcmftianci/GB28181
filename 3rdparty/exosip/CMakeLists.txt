cmake_minimum_required(VERSION 3.11)

project(exosip)

add_definitions(-DHAVE_CARES_H)
add_definitions(-DCARES_STATICLIB)

file(GLOB exosip_SRC  ${CMAKE_CURRENT_SOURCE_DIR}/src/eXcall_api.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXconf.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXinsubscription_api.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXmessage_api.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXoptions_api.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXosip.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXpublish_api.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXregister_api.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXsubscription_api.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXtl_dtls.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXtl_tcp.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXtl_tls.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXtl_udp.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXtransport.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXutils.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/inet_ntop.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jauth.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jcall.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jcallback.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jdialog.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jevents.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jnotify.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jpipe.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jpublish.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jreg.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jrequest.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jresponse.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jsubscribe.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/milenage.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/rijndael.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/sdp_offans.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/udp.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/eXosip2/eX_call.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/eXosip2/eX_message.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/eXosip2/eX_options.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/eXosip2/eX_publish.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/eXosip2/eX_refer.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/eXosip2/eX_register.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/eXosip2/eX_setup.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/eXosip2/eX_subscribe.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/eXosip2/eXosip.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXosip2.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/eXtransport.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/inet_ntop.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/jpipe.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/milenage.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/rijndael.h)
                    # ${CMAKE_CURRENT_SOURCE_DIR}/platform/vsnet/eXosip2.def)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/3rdparty/osip/include)
add_library(exosip STATIC ${exosip_SRC})

target_link_libraries(exosip PRIVATE osipparser)