cmake_minimum_required(VERSION 3.11)

project(osip)

# add_definitions(-DWIN32 -DENABLE_TRACE -DSYSTEM_LOGGER_ENABLED -D_CRT_SECURE_NO_DEPRECATE -D_LIB)

add_definitions(-DDEBUG_MEM -D_CRT_SECURE_NO_WARNINGS)

file(GLOB osipparser_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_accept.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_accept_encoding.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_accept_language.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_alert_info.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_allow.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_authentication_info.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_authorization.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_body.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_call_id.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_call_info.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_contact.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_content_disposition.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_content_encoding.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_content_length.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_content_type.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_cseq.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_error_info.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_from.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_header.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_list.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_md5c.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_message.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_message_parse.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_message_to_str.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_mime_version.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_parser_cfg.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_port.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_proxy_authenticate.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_proxy_authentication_info.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_proxy_authorization.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_record_route.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_route.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_to.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_uri.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_via.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/osip_www_authenticate.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/sdp_accessor.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/sdp_message.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_accept.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_accept_encoding.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_accept_language.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_alert_info.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_allow.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_authorization.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/internal.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/osip_body.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_call_id.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_call_info.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/osip_const.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_contact.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_content_disposition.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_content_encoding.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_content_length.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_content_type.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_cseq.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_error_info.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_from.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_header.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/osip_headers.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/osip_list.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/osip_md5.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/osip_message.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_mime_version.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/osip_parser.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/osip_port.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_proxy_authenticate.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_proxy_authorization.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_record_route.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_route.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_to.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/osip_uri.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_via.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_www_authenticate.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/osipparser2/parser.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/sdp_message.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_authentication_info.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/osipparser2/headers/osip_proxy_authentication_info.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/platform/vsnet/osipparser2.def)



add_library(osipparser STATIC ${osipparser_SRC})

target_include_directories(osipparser PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)


file(GLOB osip_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/fsm_misc.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/ict.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/ict_fsm.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/ist.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/ist_fsm.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/nict.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/nict_fsm.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/nist.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/nist_fsm.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/osip.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/osip_dialog.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/osip_event.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/osip_time.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/osip_transaction.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/port_condv.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/port_fifo.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/port_sema.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/port_thread.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/fsm.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/include/osip2/internal.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/include/osip2/osip.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/include/osip2/osip_condv.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/include/osip2/osip_dialog.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/include/osip2/osip_fifo.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/include/osip2/osip_mt.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/osip2/xixt.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/platform/vsnet/osip2.def)

add_library(osip SHARED ${osip_SRC})
target_include_directories(osip PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(osip PRIVATE osipparser)