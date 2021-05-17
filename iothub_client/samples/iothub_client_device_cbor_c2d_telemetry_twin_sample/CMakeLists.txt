#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

if(NOT ${use_mqtt})
    message(FATAL_ERROR "iothub_client_device_cbor_c2d_telemetry_twin_sample being generated without MQTT support")
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
set(iothub_client_device_cbor_c2d_telemetry_twin_sample_c_files
    iothub_client_device_cbor_c2d_telemetry_twin_sample.c
)

if(${use_sample_trusted_cert})
    add_definitions(-DSET_TRUSTED_CERT_IN_SAMPLES)
    include_directories(${PROJECT_SOURCE_DIR}/certs)
    set(iothub_client_device_cbor_c2d_telemetry_twin_sample_c_files ${iothub_client_device_cbor_c2d_telemetry_twin_sample_c_files}
        ${PROJECT_SOURCE_DIR}/certs/certs.c)
endif()

add_executable(iothub_client_device_cbor_c2d_telemetry_twin_sample
    ${iothub_client_device_cbor_c2d_telemetry_twin_sample_c_files}
)

target_link_libraries(iothub_client_device_cbor_c2d_telemetry_twin_sample
    iothub_client
)

target_link_libraries(iothub_client_device_cbor_c2d_telemetry_twin_sample
    ${tinycbor}
)

find_path(TINYCBOR_INCLUDE_DIR cbor.h
    PATH_SUFFIXES
        if(WIN32) tinycbor/src src
        elseif(UNIX) tinycbor #/usr/local/include/tinycbor
        endif()
)
target_include_directories(iothub_client_device_cbor_c2d_telemetry_twin_sample
    PRIVATE
        ${TINYCBOR_INCLUDE_DIR}
)
