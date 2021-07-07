#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

if(NOT ${use_mqtt})
    message(FATAL_ERROR "iothub_client_device_cbor_sample being generated without MQTT support")
endif()

compileAsC99()

IF(WIN32)
    #windows needs this define
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DGB_MEASURE_MEMORY_FOR_THIS -DGB_DEBUG_ALLOC)
ENDIF(WIN32)

if(MSVC)
  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:LIBCMT.lib") # To compile with intel/tinycbor
endif()

# Sample Executable
add_executable(iothub_client_device_cbor_sample
    iothub_client_device_cbor_sample.c
)

if(${use_sample_trusted_cert})
    target_compile_definitions(iothub_client_device_cbor_sample
        PUBLIC
            SET_TRUSTED_CERT_IN_SAMPLES
    )
    target_sources(iothub_client_device_cbor_sample
        PRIVATE
            ${PROJECT_SOURCE_DIR}/certs/certs.c
    )
    target_include_directories(iothub_client_device_cbor_sample
        PRIVATE
            ${PROJECT_SOURCE_DIR}/certs
    )
endif()

target_link_libraries(iothub_client_device_cbor_sample
    iothub_client
    ${tinycbor}
)

find_path(TINYCBOR_INCLUDE_DIR cbor.h
    PATH_SUFFIXES
        if(WIN32) tinycbor/src src
        elseif(UNIX) tinycbor #/usr/local/include/tinycbor
        endif()
)
target_include_directories(iothub_client_device_cbor_sample
    PRIVATE
        ${TINYCBOR_INCLUDE_DIR}
)
