
cmake_minimum_required(VERSION 3.5)

# This section turns on and off this feature
option( INCLUDE_LIBMQTTHELPER "Include libmqtthelper" ON )
if( NOT ${INCLUDE_LIBMQTTHELPER} )
    return()
endif()

project(mqtthelper)

set(MQTT_USERNAME "admin" CACHE STRING "Mqtt default username")
set(MQTT_PASSWORD "admin" CACHE STRING "Mqtt default password")

set(MQTT_DEFAULT_CERT_FILE "/usr/local/etc/client.pem" CACHE STRING "Mqtt default client cert file" )
set(MQTT_DEFAULT_KEY_FILE  "/usr/local/etc/client.key" CACHE STRING "Mqtt default client cert key" )
set(MQTT_DEFAULT_CA_PATH   "/etc/ssl/certs/"           CACHE STRING "Mqtt default ca path"         )

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/mqtthelper-config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/include/mqtthelper-config.h")

add_library(mqtthelper mqtthelper.c)

target_link_libraries (mqtthelper LINK_PUBLIC libmosquitto dbgprint select_cb)
target_include_directories(mqtthelper PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_BINARY_DIR}/include)



if(${BUILD_SHARED_LIBS})
    install(TARGETS    mqtthelper       DESTINATION /usr/local/lib )
endif()

if(${make_tests})
    add_subdirectory (tests)
endif()
