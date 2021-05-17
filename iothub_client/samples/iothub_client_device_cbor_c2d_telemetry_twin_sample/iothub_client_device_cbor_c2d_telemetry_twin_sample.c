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

#define CBOR_BUFFER_SIZE 512

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

// Connection String - Paste in the your iothub device connection string.
static const char* connection_string= "[device connection string]";
static IOTHUB_DEVICE_CLIENT_HANDLE iothub_client_handle;

// Device properties - A Car Object
typedef struct MAKER_TAG
{
    char* name;                 // reported property
    char* style;                // reported property
    uint64_t year;              // reported property
} Maker;

typedef struct STATE_TAG
{
    uint64_t max_speed;         // desired/reported property
    uint64_t software_version;  // desired/reported property
    char* vanity_plate;         // reported property
} State;

typedef struct CAR_TAG
{
    bool change_oil_reminder;   // desired/reported property
    char* last_oil_change_date; // reported property
    Maker maker;                // reported property
    State state;                // desired/reported property
} Car;

// Functions
static void create_and_configure_device_client(void);
static void connect_device_client_send_and_receive_messages(void);
static void disconnect_device_client(void);

static void serializeToCBOR(Car* car, uint8_t* cbor_buf, size_t buffer_size, size_t* out_cbor_length);
static void parseFromCBOR(DEVICE_TWIN_UPDATE_STATE update_state, Car* car, const unsigned char* cbor_payload);

static void getTwinAsyncCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback);
static void deviceReportedPropertiesTwinCallback(int status_code, void* userContextCallback);
static void deviceDesiredPropertiesTwinCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback);

/*
 * This sample utilizes the Azure IoT Hub to get the device twin document, send a reported
 * property message, and receive desired property messages all in CBOR. It also shows how to set an
 * application-defined content type (such as CBOR) for either C2D or telemetry messaging, to be used
 * with a coordinated service-side application. After 10 attempts to receive a message, the sample
 * will exit. To run this sample, the MIT licensed intel/tinycbor library must be installed. The
 * Embedded C SDK is not dependent on ny particular CBOR library. X509 self-certification is used.
 *
 * Device Twin:
 * A property named `device_count` is used. To send a device twin desired property message, select
 * your device's Device Twin tab in the Azure Portal of your IoT Hub. Add the property
 * `device_count` along with a corresponding value to the `desired` section of the twin JSON. Select
 * Save to update the twin document and send the twin message to the device. The IoT Hub will
 * translate the twin JSON into CBOR for the device to consume.
 *
 * {
 *   "properties": {
 *     "desired": {
 *       "device_count": 42,
 *     }
 *   }
 * }
 *
 * No other property names sent in a desired property message are supported. If any are sent, the
 * log will report the `device_count` property was not found.
 *
 * C2D and Telemetry:
 * To send a C2D message, select your device's Message to Device tab in the Azure Portal for your
 * IoT Hub. Under Properties, enter `$.ct` for Key, and `cbor` for Value. Enter a message in the
 * Message Body and select Send Message. After receiving a message (C2D or twin desired property) or
 * upon a message timeout, the sample will send a single telemetry message in CBOR. After 10
 * attempts to receive a message, the sample will exit.
 *
 * IMPORTANT: This sample only demonstrates how to set the expected content type for a C2D or
 * telemetry message on the device side. Only device-side implementation is shown; the corresponding
 * service-side required implementation to use this feature is not part of this sample. The Azure
 * Portal service-side application does not support CBOR translation for C2D messages, therefore any
 * correctly formatted JSON message sent from the portal will not arrive to the device as correct
 * CBOR.
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

    // Initialize the device properties - A Car Object
    Car car;
    memset(&car, 0, sizeof(Car));
    car.last_oil_change_date = "2016";
    car.maker.name = "Fabrikam";
    car.maker.style = "sedan";
    car.maker.year = 2014;
    car.state.max_speed = 100;
    car.state.software_version = 1;
    car.state.vanity_plate = "1T1";

    // Send and receive messages from IoT Hub.
    // Connection happens when a message is first sent.
    rc = IoTHubDeviceClient_GetTwinAsync(iothub_client_handle, getTwinAsyncCallback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to send a GET request for the twin document asynchronously: return code %d.\n", rc);
        exit(rc);
    }

    uint8_t reported_properties[CBOR_BUFFER_SIZE];
    size_t reported_properties_length;
    serializeToCBOR(&car, reported_properties, CBOR_BUFFER_SIZE, &reported_properties_length);
    printf("Size of encoded CBOR: %zu\n", reported_properties_length);
    rc = IoTHubDeviceClient_SendReportedState(iothub_client_handle, reported_properties, reported_properties_length, deviceReportedPropertiesTwinCallback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to send a reported property PATCH request to the IoT Hub: return code %d.\n", rc);
        exit(rc);
    }

    rc = IoTHubDeviceClient_SetDeviceTwinCallback(iothub_client_handle, deviceDesiredPropertiesTwinCallback, &car);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set the twin document callback: return code %d.\n", rc);
        exit(rc);
    }

    (void)printf("Wait for desired properties update or direct method from service. Press any key to exit sample.\r\n");
    (void)getchar();
}

static void disconnect_device_client(void)
{
    IoTHubDeviceClient_Destroy(iothub_client_handle);
    IoTHub_Deinit();
}




//
// Encoding/Decoding with chosen library
//

//  Serialize Car object to CBOR blob. To be sent as a twin document with reported properties.
static void serializeToCBOR(Car* car, uint8_t* cbor_buf, size_t buffer_size, size_t* out_cbor_length)
{
    CborEncoder cbor_encoder_root;
    CborEncoder cbor_encoder_root_container;
    CborEncoder cbor_encoder_maker;
    CborEncoder cbor_encoder_state;

    // WARNING: Check the return of all API calls when developing your solution. Many return checks
    //          are ommited from this sample for simplification.

    // Only reported properties.
    cbor_encoder_init(&cbor_encoder_root, cbor_buf, buffer_size, 0);
    (void)cbor_encoder_create_map(&cbor_encoder_root, &cbor_encoder_root_container, 3);

        (void)cbor_encode_text_string(&cbor_encoder_root_container, "last_oil_change_date", strlen("last_oil_change_date"));
        (void)cbor_encode_text_string(&cbor_encoder_root_container, car->last_oil_change_date, strlen(car->last_oil_change_date));

        (void)cbor_encode_text_string(&cbor_encoder_root_container, "maker", strlen("maker"));
        (void)cbor_encoder_create_map(&cbor_encoder_root_container, &cbor_encoder_maker, 3);
            (void)cbor_encode_text_string(&cbor_encoder_maker, "name", strlen("name"));
            (void)cbor_encode_text_string(&cbor_encoder_maker, car->maker.name, strlen(car->maker.name));
            (void)cbor_encode_text_string(&cbor_encoder_maker, "style", strlen("style"));
            (void)cbor_encode_text_string(&cbor_encoder_maker, car->maker.style, strlen(car->maker.style));
            (void)cbor_encode_text_string(&cbor_encoder_maker, "year", strlen("year"));
            (void)cbor_encode_uint(&cbor_encoder_maker, car->maker.year);
        (void)cbor_encoder_close_container(&cbor_encoder_root_container, &cbor_encoder_maker);

        (void)cbor_encode_text_string(&cbor_encoder_root_container, "state", strlen("state"));
        (void)cbor_encoder_create_map(&cbor_encoder_root_container, &cbor_encoder_state, 3);
            (void)cbor_encode_text_string(&cbor_encoder_state, "max_speed", strlen("max_speed"));
            (void)cbor_encode_simple_value(&cbor_encoder_state, car->state.max_speed);
            (void)cbor_encode_text_string(&cbor_encoder_state, "software_version", strlen("software_version"));
            (void)cbor_encode_uint(&cbor_encoder_state, car->state.software_version);
            (void)cbor_encode_text_string(&cbor_encoder_state, "vanity_plate", strlen("vanity_plate"));
            (void)cbor_encode_text_string(&cbor_encoder_state, car->state.vanity_plate, strlen(car->state.vanity_plate));
        (void)cbor_encoder_close_container(&cbor_encoder_root_container, &cbor_encoder_state);

    (void)cbor_encoder_close_container(&cbor_encoder_root, &cbor_encoder_root_container);

    *out_cbor_length = cbor_encoder_get_buffer_size(&cbor_encoder_root, cbor_buf);
}

// Convert the desired properties of the Device Twin CBOR blob from IoT Hub into a Car Object.
static void parseFromCBOR(DEVICE_TWIN_UPDATE_STATE update_state, Car* car, const unsigned char* cbor_payload)
{
    CborParser cbor_parser;
    CborValue root;
    CborValue state_root;

    // Only desired properties.
    CborValue change_oil_reminder;
    CborValue max_speed;
    CborValue software_version;

    // WARNING: Check the return of all API calls when developing your solution. Many return checks
    //          are ommited from this sample for simplification.
    CborError rc;

    rc = cbor_parser_init(cbor_payload, strlen((char*)cbor_payload), 0, &cbor_parser, &root);
    if (rc)
    {
        printf("Failed to initiate parser: CborError %d.", rc);
        exit(rc);
    }

    if (update_state == DEVICE_TWIN_UPDATE_COMPLETE)
    {
        rc = cbor_value_map_find_value(&root, "desired", &root);
        if (rc)
        {
            printf("Error when searching for %s: CborError %d.", "desired", rc);
            exit(rc);
        }
    }

    if (cbor_value_map_find_value(&root, "change_oil_reminder", &change_oil_reminder) == CborNoError)
    {
        if (cbor_value_is_valid(&change_oil_reminder))
        {
            if (cbor_value_is_boolean(&change_oil_reminder))
            {
                (void)cbor_value_get_boolean(&change_oil_reminder, &car->change_oil_reminder);
            }
        }
    }

    if (cbor_value_map_find_value(&root, "state", &state_root) == CborNoError)
    {
        if (cbor_value_is_valid(&state_root))
        {
            if (cbor_value_map_find_value(&state_root, "max_speed", &max_speed) == CborNoError)
            {
                if (cbor_value_is_valid(&max_speed))
                {
                    if (cbor_value_is_unsigned_integer(&max_speed))
                    {
                        (void)cbor_value_get_uint64(&max_speed, &car->state.max_speed);
                    }
                }
            }

            if (cbor_value_map_find_value(&root, "software_version", &software_version) == CborNoError)
            {
                if (cbor_value_is_valid(&software_version))
                {
                    if (cbor_value_is_unsigned_integer(&software_version))
                    {
                        (void)cbor_value_get_uint64(&software_version, &car->state.software_version);
                    }
                }
            }
        }
    }
}


//
// Callbacks
//

// Callback for async GET request to IoT Hub for entire Device Twin document.
static void getTwinAsyncCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback)
{
    (void)update_state;
    (void)userContextCallback;

    printf("getTwinAsyncCallback payload:\n%.*s\n", (int)size, payload);
    for (uint i = 0; i < size; i++)
    {
        printf("%0X ", payload[i]);
    }
    printf("\n");

    Car* car = (Car*)userContextCallback;
    Car desired_car;
    memset(&desired_car, 0, sizeof(Car));
    parseFromCBOR(update_state, &desired_car, payload);

    printf("Received a desired change_oil_reminder = %d\n", desired_car.change_oil_reminder);
    printf("Received a desired max_speed = %" PRIu64 "\n", desired_car.state.max_speed);
    printf("Received a desired software_version = %" PRIu64 "\n", desired_car.state.software_version);
}

// Callback for when device sends reported properties to IoT Hub, and IoT Hub updates the Device
// Twin document.
static void deviceReportedPropertiesTwinCallback(int status_code, void* userContextCallback)
{
    (void)userContextCallback;
    printf("deviceReportedPropertiesTwinCallback: Result status code: %d\n", status_code);
}

// Callback for when IoT Hub updates the desired properties of the Device Twin document.
static void deviceDesiredPropertiesTwinCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback)
{
    (void)update_state;
    (void)size;

    printf("deviceDesiredPropertiesTwinCallback payload:\n%.*s\n", (int)size, payload);

    Car* car = (Car*)userContextCallback;
    Car desired_car;
    memset(&desired_car, 0, sizeof(Car));
    parseFromCBOR(update_state, &desired_car, payload);

    if (desired_car.change_oil_reminder != car->change_oil_reminder)
    {
        printf("Received a desired change_oil_reminder = %d\n", desired_car.change_oil_reminder);
        car->change_oil_reminder = desired_car.change_oil_reminder;
    }

    if (desired_car.state.max_speed != 0 && desired_car.state.max_speed != car->state.max_speed)
    {
        printf("Received a desired max_speed = %" PRIu64 "\n", desired_car.state.max_speed);
        car->state.max_speed = desired_car.state.max_speed;
    }

    if (desired_car.state.software_version != 0 && desired_car.state.software_version != car->state.software_version)
    {
        printf("Received a desired software_version = %" PRIu64 "\n", desired_car.state.software_version);
        car->state.software_version = desired_car.state.software_version;
    }

    uint8_t reported_properties[CBOR_BUFFER_SIZE];
    size_t reported_properties_length;
    serializeToCBOR(car, reported_properties, CBOR_BUFFER_SIZE, &reported_properties_length);

    (void)IoTHubDeviceClient_SendReportedState(iothub_client_handle, reported_properties, reported_properties_length, deviceReportedPropertiesTwinCallback, NULL);
}
