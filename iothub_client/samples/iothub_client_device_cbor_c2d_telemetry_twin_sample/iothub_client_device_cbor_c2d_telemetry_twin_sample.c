// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_macro_utils/macro_utils.h"

#include "iothub.h"
#include "iothub_client_options.h"
#include "iothub_device_client.h"
#include "iothub_message.h"

//#ifdef __GNUC__
//#pragma GCC diagnostic push
// warning within intel/tinycbor: conversion from 'int' to uint8_t'
//#pragma GCC diagnostic ignored "-Wconversion"
//#endif
#include "cbor.h"
//#ifdef __GNUC__
//#pragma GCC diagnostic pop
//#endif

#define REPORTED_PROPERTY_BUFFER_SIZE 512

// Trusted Cert -- Turn on via build flag
#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    #include "certs.h"
#endif

// Transport Layer Protocal -- Uncomment the protocol you wish to use.
#define SAMPLE_MQTT
//#define SAMPLE_MQTT_OVER_WEBSOCKETS

#ifdef SAMPLE_MQTT
    #include "iothubtransportmqtt.h"
    static IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = MQTT_Protocol;
#elif defined SAMPLE_MQTT_OVER_WEBSOCKETS
    #include "iothubtransportmqtt_websockets.h"
    static IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = MQTT_WebSocket_Protocol;
#endif

// Connection String -- Paste in the your iothub device connection string.
static const char* connection_string= "[device connection string]";
static IOTHUB_DEVICE_CLIENT_HANDLE iothub_client_handle;

// Device Twin Properties
static uint8_t reported_property_buffer[REPORTED_PROPERTY_BUFFER_SIZE];
static size_t reported_property_length;
static char* twin_desired_property = "desired";

static char* twin_property_manufacturer_name = "manufacturer";
static char* twin_property_manufacturer_make_name = "make";
static char* twin_property_manufacturer_style_name = "style";
static char* twin_property_manufacturer_year_name = "year";
static char* twin_property_state_name = "state";
static char* twin_property_state_max_speed_name = "max_speed";
static char* twin_property_state_software_version_name = "software_version";
static char* twin_property_state_vanity_plate_name = "vanity_plate";
static char* twin_property_change_oil_reminder_name = "change_oil_reminder";
static char* twin_property_last_oil_change_date_name = "last_oil_change_date";

typedef struct MANUFACTURER_TAG
{
    char* make;                 // reported property
    char* model;                // reported property
    uint64_t year;              // reported property
} Manufacturer;

typedef struct STATE_TAG
{
    uint64_t max_speed;         // desired/reported property
    double software_version;    // desired/reported property
    char* vanity_plate;         // reported property
} State;

typedef struct CAR_TAG
{
    bool change_oil_reminder;   // desired/reported property
    char* last_oil_change_date; // reported property
    Manufacturer manufacturer;  // reported property
    State state;                // desired/reported property
} Car;

static Car device_car = { .change_oil_reminder = false,
                          .last_oil_change_date = "May 4, 2016",
                          .manufacturer = { .make = "Fabrikam",
                                            .style = "sedan",
                                            .year = 2014 },
                          .state = { .max_speed = 100,
                                     .software_version = 1.1,
                                     .vanity_plate = "1T1" } };

// Functions
static void create_and_configure_device_client(void);
static void connect_device_client_send_and_receive_messages(void);
static void disconnect_device_client(void);

static bool parse_cbor_desired_property(DEVICE_TWIN_UPDATE_STATE update_state, Car* car, const unsigned char* cbor_payload);
static void build_cbor_reported_property(Car* car, uint8_t* reported_property_buffer, size_t reported_property_buffer_size, size_t* out_reported_property_length);

static void get_twin_async_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback);
static void twin_desired_properties_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback);
static void twin_reported_properties_callback(int status_code, void* userContextCallback);

/*
 * This sample utilizes the Azure IoT Hub to get the device twin document, send a reported
 * property message, and receive desired property messages all in CBOR data format. It also shows
 * how to set the content type system property for C2D and telemetry messaging. After 10 attempts to
 * receive a C2D or desired property message, the sample will exit.
 *
 * To run this sample, Intel's MIT licensed TinyCBOR library must be installed. The Embedded C SDK
 * is not dependent on any particular CBOR library. X509 self-certification is used.
 *
 * Device Twin:
 * There are three desired properties supported for this sample: `change_oil_remainder`,
 * `state`:`max_speed`, and `state`:`software_version`. To send a device twin desired property
 * message, select your device's Device Twin tab in the Azure Portal of your IoT Hub. Add one of the
 * avilable desired properties along with a corresponding value of the supported value type to the
 * `desired` section of the twin JSON. Select Save to update the twin document and send the twin
 * message to the device. The IoT Hub will translate the twin JSON into CBOR for the device to
 * consume and decode.
 *
 * "properties": {
 *     "desired": {
 *         "change_oil_remainder": true,
 *         "state": {
 *             "max_speed": 200,
 *             "software_version": 4.2
 *         }
 *     }
 * }
 *
 * No other property names sent in a desired property message are supported.
 *
 * C2D Messaging:
 * To send a C2D message, select your device's Message to Device tab in the Azure Portal for your
 * IoT Hub. Under Properties, enter the SDK-defined content type system property name `$.ct` for
 * Key, and the application-defined value `application/cbor` for Value. This value must be agreed
 * upon between the device and service side applications to use the content type system property for
 * C2D messaging. Enter a message in the Message Body and select Send Message. The Key and Value
 * will appear as a URL-encoded key-value pair appended to the topic: `%24.ct=application%2Fcbor`.
 *
 * NOTE: The Azure Portal will NOT translate a JSON formatted message into CBOR, nor will it encode
 * the message in binary. Therefore, this sample only demonstrates how to parse the topic for the
 * content type system property. It is up to the service application to encode correctly formatted
 * CBOR (or other specified content type) and the device application to correctly decode it.
 *
 * Telemetry:
 * The sample will automatically send CBOR formatted messages after each attempt to receive a C2D or
 * desired property message. The SDK-defined content type system property name `$.ct` and the
 * application-defined value `application/cbor` will appear as a URL-encoded key-value pair appended
 * to the topic: `%24.ct=application%2Fcbor`. This value must be agreed upon between the device and
 * service side applications to use the content type system property for Telemetry messaging.
 */

int main(void)
{
    create_and_configure_device_client();

    connect_device_client_send_and_receive_messages();

    disconnect_device_client();

    return 0;
}

static void create_and_configure_device_client(void)
{
    int rc; // 0 is OK.

    rc = IoTHub_Init();
    if (rc != 0)
    {
        (void)printf("Failed to initialize the IoT Hub platform.\n");
        exit(rc);
    }

    iothub_client_handle = IoTHubDeviceClient_CreateFromConnectionString(connection_string, protocol);
    if (iothub_client_handle == NULL)
    {
        (void)printf("Failed to create device client from connection string.\n");
        exit(EXIT_FAILURE);
    }

    //
    // Set Options
    //
    bool trace_on = true; // Debugging
    rc = IoTHubDeviceClient_SetOption(iothub_client_handle, OPTION_LOG_TRACE, &trace_on);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set option for %s: return code %d.\n", OPTION_LOG_TRACE, rc);
        exit(rc);
    }

    // Set the auto URL Encoder (recommended for MQTT). Please use this option unless you are URL
    // Encoding inputs yourself. ONLY valid for use with MQTT.
    bool url_encode_on = true;
    rc = IoTHubDeviceClient_SetOption(iothub_client_handle, OPTION_AUTO_URL_ENCODE_DECODE, &url_encode_on);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set option for %s: return code %d.\n", OPTION_AUTO_URL_ENCODE_DECODE, rc);
        exit(rc);
    }

    // Format ONLY the device twin document using CBOR.
    // ONLY valid for use with MQTT. Must occur prior to CONNECT.
    OPTION_TWIN_CONTENT_TYPE_VALUE ct = OPTION_TWIN_CONTENT_TYPE_CBOR;
    rc = IoTHubDeviceClient_SetOption(iothub_client_handle, OPTION_TWIN_CONTENT_TYPE, &ct);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set option for %s: return code %d.\n", OPTION_TWIN_CONTENT_TYPE, rc);
        exit(rc);
    }

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    // Use SDK-supplied trusted certificates to run the sample.
    // ONLY to be used for the sample. **NOT to be used in production code.**
    rc = IoTHubDeviceClient_SetOption(iothub_client_handle, OPTION_TRUSTED_CERT, certificates);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set option for %s: return code %d.\n", OPTION_TRUSTED_CERT, rc);
        exit(rc);
    }
#endif
}

static void connect_device_client_send_and_receive_messages(void)
{
    int rc;

    //
    // Send and receive messages from IoT Hub asynchronously. Connection occurs when a message is first sent.
    //

    // Send asynchronous GET request for twin document.
    // Set GET twin document callback.
    rc = IoTHubDeviceClient_GetTwinAsync(iothub_client_handle, get_twin_async_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to send a GET request for the twin document asynchronously: return code %d.\n", rc);
        exit(rc);
    }

    // Set callback for twin desired property PATCH messages from IoT Hub.
    rc = IoTHubDeviceClient_SetDeviceTwinCallback(iothub_client_handle, twin_desired_properties_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set the twin document callback: return code %d.\n", rc);
        exit(rc);
    }

    // Send reported properties PATCH message.
    // Set callback for twin reported property response from IoT Hub.
    build_cbor_reported_property(reported_property_buffer, REPORTED_PROPERTY_BUFFER_SIZE, &reported_property_length);
    rc = IoTHubDeviceClient_SendReportedState(iothub_client_handle, reported_property_buffer, reported_property_length, twin_reported_properties_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to send a reported property PATCH request to the IoT Hub: return code %d.\n", rc);
        exit(rc);
    }

    (void)printf("Wait for desired properties message from IoT Hub. Press any key to exit sample.\r\n");
    (void)getchar();
}

static void disconnect_device_client(void)
{
    IoTHubDeviceClient_Destroy(iothub_client_handle);
    IoTHub_Deinit();
}

//
// Callbacks
//
static void get_twin_async_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback)
{
    (void)userContextCallback;

    printf("get_twin_async_callback payload: ");
    for (uint i = 0; i < size; i++)
    {
        printf("%0X ", payload[i]);
    }
    printf("\n");

    Car iot_hub_car;
    memset(&iot_hub_car, 0, sizeof(Car));
    parse_cbor_desired_property(update_state, payload, &iot_hub_car);

    // Update device_car to match twin desired properties received from IoT Hub.
    device_car.change_oil_reminder = iot_hub_car.change_oil_reminder;
    device_car.state.max_speed = iot_hub_car.state.max_speed;
    device_car.state.software_version = iot_hub_car.state.software_version;
}

static void twin_desired_properties_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback)
{
    (void)userContextCallback;

    printf("twin_desired_properties_callback payload: ");
    for (uint i = 0; i < size; i++)
    {
        printf("%0X ", payload[i]);
    }
    printf("\n");

    Car iot_hub_car;
    memset(&iot_hub_car, 0, sizeof(Car));
    parse_cbor_desired_property(update_state, payload, &iot_hub_car);

    // Update device_car if twin desired property received from IoT Hub is different than what it stored on device.
    if (device_car.change_oil_reminder != iot_hub_car.change_oil_reminder)
    {
        printf("Received an updated change_oil_reminder = %s\n", iot_hub_car.change_oil_reminder ? "true" : "false");
        device_car.change_oil_reminder = iot_hub_car.change_oil_reminder;
    }

    if (device_car.state.max_speed != iot_hub_car.state.max_speed)
    {
        if (iot_hub_car.state.max_speed > 260)
        {
            printf("Received an updated max_speed that exceeds device capability: %" PRIu64 ". Rejecting update.\n")
        }
        else
        {
            printf("Received an updated max_speed = %" PRIu64 "\n", iot_hub_car.state.max_speed);
            device_car.state.max_speed = iot_hub_car.state.max_speed;
        }
    }

    if (device_car.state.software_version != iot_hub_car.state.software_version)
    {
        printf("Received an updated software_version = %f\n", iot_hub_car.state.software_version);
        device_car.state.software_version = iot_hub_car.state.software_version;
    }

    // Update IoT Hub with current device properties.
    build_cbor_reported_property(reported_property_buffer, REPORTED_PROPERTY_BUFFER_SIZE, &reported_property_length);
    rc = IoTHubDeviceClient_SendReportedState(iothub_client_handle, reported_property_buffer, reported_property_length, twin_reported_properties_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to send a reported property PATCH request to the IoT Hub: return code %d.\n", rc);
        exit(rc);
    }
}

static void twin_reported_properties_callback(int status_code, void* userContextCallback)
{
    (void)userContextCallback;
    printf("twin_reported_properties_callback: Result status code: %d\n", status_code);
}

//
// Encoding/Decoding with CBOR library
//
static bool parse_cbor_desired_property(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, Car* out_car)
{
    CborError rc; // CborNoError == 0
    bool result;

    CborParser parser;
    CborValue root;
    CborValue state_root;

    CborValue change_oil_reminder;
    CborValue max_speed;
    CborValue software_version;

    rc = cbor_parser_init(payload, strlen((char*)payload), 0, &parser, &root);
    if (rc)
    {
        printf("Failed to initiate parser: CborError %d.", rc);
        exit(rc);
    }

    // Check if this is the full twin document or only the desired properties.
    if (update_state == DEVICE_TWIN_UPDATE_COMPLETE) // full twin document (desried and reported)
    {
        rc = cbor_value_map_find_value(&root, twin_desired_property, &root);
        if (rc)
        {
            printf("Error when searching for %s: CborError %d.", twin_desired_property, rc);
            exit(rc);
        }
    }

    // change_oil_reminder
    rc = cbor_value_map_find_value(&root, twin_property_change_oil_reminder_name, &change_oil_reminder);
    if (rc)
    {
        IOT_SAMPLE_LOG_ERROR("Error when searching for %s: CborError %d.", twin_property_change_oil_reminder_name, rc);
        exit(rc);
    }
    if (cbor_value_is_valid(&change_oil_reminder))
    {
        if (cbor_value_is_boolean(&change_oil_reminder))
        {
            rc = cbor_value_get_boolean(&change_oil_reminder, &out_car->change_oil_reminder);
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to get boolean value of property %s: CborError %d.", twin_property_change_oil_reminder_name, rc);
                exit(rc);
            }
            else
            {
                IOT_SAMPLE_LOG("Parsed desired property `%s`: %" PRIi64, twin_property_change_oil_reminder_name, out_car->change_oil_reminder);
                result = true;
            }
        }
        else
        {
            IOT_SAMPLE_LOG("`%s` property value was not a boolean.", twin_property_change_oil_reminder_name);
            result = false;
        }
    }
    else
    {
        IOT_SAMPLE_LOG("`%s` property name was not found in desired property message.", twin_property_change_oil_reminder_name);
        result = false;
    }

    // state
    rc = cbor_value_map_find_value(&root, twin_property_state_name, &state_root);
    if (rc)
    {
        IOT_SAMPLE_LOG_ERROR("Error when searching for %s: CborError %d.", twin_property_state_name, rc);
        exit(rc);
    }
    if (cbor_value_is_valid(&state_root))
    {
        // state : max_speed
        rc = cbor_value_map_find_value(&root, twin_property_state_max_speed_name, &max_speed);
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Error when searching for %s: CborError %d.", twin_property_state_max_speed_name, rc);
            exit(rc);
        }
        if (cbor_value_is_valid(&max_speed))
        {
            if (cbor_value_is_unsigned_integer(&max_speed))
            {
                rc = cbor_value_get_uint64(&max_speed, &out_car->state.max_speed);
                if (rc)
                {
                    IOT_SAMPLE_LOG_ERROR("Failed to get uint64 value of property %s: CborError %d.", twin_property_state_max_speed_name, rc);
                    exit(rc);
                }
                else
                {
                    IOT_SAMPLE_LOG("Parsed desired property `%s`: %" PRIu64, twin_property_state_max_speed_name, out_car->state.max_speed);
                    result = true;
                }
            }
            else
            {
                IOT_SAMPLE_LOG("`%s` property value was not an unsigned integer.", twin_property_state_max_speed_name);
                result = false;
            }
        }
        else
        {
            IOT_SAMPLE_LOG("`%s` property name was not found in desired property message.", twin_property_state_max_speed_name);
            result = false;
        }

        // state : software_version
        rc = cbor_value_map_find_value(&root, twin_property_state_software_version_name, &software_version);
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Error when searching for %s: CborError %d.", twin_property_state_software_version_name, rc);
            exit(rc);
        }
        if (cbor_value_is_valid(&software_version))
        {
            if (cbor_value_is_double(&software_version))
            {
                rc = cbor_value_get_double(&software_version, &out_car->state.software_version);
                if (rc)
                {
                    IOT_SAMPLE_LOG_ERROR("Failed to get double value of property %s: CborError %d.", twin_property_state_software_version_name, rc);
                    exit(rc);
                }
                else
                {
                    IOT_SAMPLE_LOG("Parsed desired property `%s`: %" PRIu64, twin_property_state_software_version_name, out_car->state.software_version);
                    result = true;
                }
            }
            else
            {
                IOT_SAMPLE_LOG("`%s` property value was not a double.", twin_property_state_software_version_name);
                result = false;
            }
        }
        else
        {
            IOT_SAMPLE_LOG("`%s` property name was not found in desired property message.", twin_property_state_software_version_name);
            result = false;
        }
    }
    else
    {
        IOT_SAMPLE_LOG("`%s` property name was not found in desired property message.", twin_property_state_name);
        result = false;
    }

    return result;
}

static void build_cbor_reported_property(uint8_t* reported_property_buffer, size_t reported_property_buffer_size, size_t* out_reported_property_length)
{
    CborError rc; // CborNoError == 0

    CborEncoder encoder;
    CborEncoder encoder_map;
    CborEncoder manufacturer_map;
    CborEncoder state_map;

    cbor_encoder_init(&encoder, reported_property_buffer, reported_property_buffer_size, 0);

    // Encoder Map
    rc = cbor_encoder_create_map(&encoder, &encoder_map, 3);
    if (rc)
    {
        IOT_SAMPLE_LOG_ERROR("Failed to create encoder map: CborError %d.", rc);
        exit(rc);
    }

        // change_oil_reminder
        rc = cbor_encode_text_string(&encoder_map, twin_property_change_oil_reminder_name, strlen(twin_property_change_oil_reminder_name));
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", twin_property_change_oil_reminder_name, rc);
            exit(rc);
        }
        rc = cbor_encode_boolean(&encoder_map, device_car.change_oil_reminder);
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Failed to encode boolean value '%s': CborError %d.", device_car.change_oil_reminder ? "true" : "false", rc);
            exit(rc);
        }

        // last_oil_change_date
        rc = cbor_encode_text_string(&encoder_map, twin_property_last_oil_change_date_name, strlen(twin_property_last_oil_change_date_name));
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", twin_property_last_oil_change_date_name, rc);
            exit(rc);
        }
        rc = cbor_encode_text_string(&encoder_map, device_car.last_oil_change_date, strlen(device_car.last_oil_change_date));
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", device_car.last_oil_change_date, rc);
            exit(rc);
        }

        // Manufacturer Map
        rc = cbor_encode_text_string(&encoder_map, twin_property_manufacturer_name, strlen(twin_property_manufacturer_name));
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", twin_property_manufacturer_name, rc);
            exit(rc);
        }
        rc = cbor_encoder_create_map(&encoder_map, &manufacturer_map, 3);
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Failed to create %s map: CborError %d.", twin_property_manufacturer_name, rc);
            exit(rc);
        }

            // manufacturer: make
            rc = cbor_encode_text_string(&manufacturer_map, twin_property_manufacturer_make_name, strlen(twin_property_manufacturer_make_name));
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", twin_property_manufacturer_make_name, rc);
                exit(rc);
            }
            rc = cbor_encode_text_string(&manufacturer_map, device_car.manufacturer.make, strlen(device_car.manufacturer.make));
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.",  device_car.manufacturer.make, rc);
                exit(rc);
            }

            // manufacturer: style
            rc = cbor_encode_text_string(&manufacturer_map, twin_property_manufacturer_style_name, strlen(twin_property_manufacturer_style_name));
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", twin_property_manufacturer_style_name, rc);
                exit(rc);
            }
            rc = cbor_encode_text_string(&manufacturer_map, device_car.manufacturer.style, strlen(device_car.manufacturer.style));
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.",  device_car.manufacturer.style, rc);
                exit(rc);
            }

            // manufacturer: year
            rc = cbor_encode_text_string(&manufacturer_map, twin_property_manufacturer_year_name, strlen(twin_property_manufacturer_year_name));
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", twin_property_manufacturer_year_name, rc);
                exit(rc);
            }
            rc = cbor_encode_uint(&manufacturer_map, device_car.manufacturer.year);
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode int '%d': CborError %d.", device_car.manufacturer.year, rc);
                exit(rc);
            }

        rc = cbor_encoder_close_container(&encoder_map, &manufacturer_map);
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Failed to close %s container: CborError %d.", twin_property_manufacturer_name, rc);
            exit(rc);
        }

        // State Map
        rc = cbor_encode_text_string(&encoder_map, twin_property_state_name, strlen(twin_property_state_name));
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", twin_property_state_name, rc);
            exit(rc);
        }
        rc = cbor_encoder_create_map(&encoder_map, &state_map, 3);
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Failed to create %s map: CborError %d.", twin_property_state_name, rc);
            exit(rc);
        }

            // state: max_speed
            rc = cbor_encode_text_string(&state_map, twin_property_state_max_speed_name, strlen(twin_property_state_max_speed_name));
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", twin_property_state_max_speed_name, rc);
                exit(rc);
            }
            rc = cbor_encode_uint(&state_map, device_car.state.max_speed);
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode int '%d': CborError %d.", device_car.state.max_speed, rc);
                exit(rc);
            }

            // state: software_version
            rc = cbor_encode_text_string(&state_map, twin_property_state_software_version_name, strlen(twin_property_state_software_version_name));
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", twin_property_state_software_version_name, rc);
                exit(rc);
            }
            rc = cbor_encode_double(&state_map, device_car.state.software_version);
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode double '%f': CborError %d.", device_car.state.software_version, rc);
                exit(rc);
            }

            // state: vanity_plate
            rc = cbor_encode_text_string(&state_map, twin_property_state_vanity_plate_name, strlen(twin_property_state_vanity_plate_name));
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.", twin_property_state_vanity_plate_name, rc);
                exit(rc);
            }
            rc = cbor_encode_text_string(&state_map, device_car.state.vanity_plate, strlen(device_car.state.vanity_plate));
            if (rc)
            {
                IOT_SAMPLE_LOG_ERROR("Failed to encode text string '%s': CborError %d.",  device_car.state.vanity_plate, rc);
                exit(rc);
            }

        rc = cbor_encoder_close_container(&encoder_map, &state_map);
        if (rc)
        {
            IOT_SAMPLE_LOG_ERROR("Failed to close %s container: CborError %d.", twin_property_state_name, rc);
            exit(rc);
        }

    rc = cbor_encoder_close_container(&encoder, &encoder_map);
    if (rc)
    {
        IOT_SAMPLE_LOG_ERROR("Failed to close container: CborError %d.", rc);
        exit(rc);
    }

    *out_reported_property_length = cbor_encoder_get_buffer_size(&encoder, reported_property_buffer);
}
