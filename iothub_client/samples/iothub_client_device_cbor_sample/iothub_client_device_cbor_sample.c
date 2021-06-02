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

#include "cbor.h"

#define REPORTED_PROPERTY_BUFFER_SIZE 512
#define TELEMETRY_MESSAGE_BUFFER_SIZE 128

#define MAX_MESSAGE_COUNT 10
#define TIMEOUT_RECEIVE_MS (30 * 1000)

#define CAR_MAX_SPEED 260

// Trusted Cert -- Turn on via build flag
#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    #include "certs.h"
#endif

// Transport Layer Protocol -- Uncomment the protocol you wish to use.
#define SAMPLE_MQTT
//#define SAMPLE_MQTT_OVER_WEBSOCKETS

#ifdef SAMPLE_MQTT
    #include "iothubtransportmqtt.h"
    static IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = MQTT_Protocol;
#elif defined SAMPLE_MQTT_OVER_WEBSOCKETS
    #include "iothubtransportmqtt_websockets.h"
    static IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = MQTT_WebSocket_Protocol;
#endif

/**
 * The content type system property for C2D and/or telemetry messages will appear as a key-value
 * pair appended to the topic. The key is SDK-defined as `$.ct` and URL-encoded as `%24.ct`. The
 * value is application-defined and must be agreed upon between the device and service side
 * applications. Examples for this value include `text/plain` and `application/json`. To
 * demonstrate setting the content type system property, this sample uses `application/cbor`.
 * See iothub_message.h for more system properties available to set for C2D and telemetry messaging.
 */
#define CONTENT_TYPE_C2D "application/cbor" // application-defined
#define CONTENT_TYPE_TELEMETRY "application/cbor" // application-defined

// Connection String -- Paste in the iothub device connection string.
static const char* connection_string = "[device connection string]";

static IOTHUB_DEVICE_CLIENT_HANDLE iothub_client_handle;
static IOTHUB_MESSAGE_HANDLE message_handle;

// Telemetry
static char* const telemetry_property_engine_temperature_name = "engine_temperature";
static uint64_t telemetry_message_id = 0;

// Device Twin Properties
static uint8_t reported_property_buffer[REPORTED_PROPERTY_BUFFER_SIZE];
static size_t reported_property_length;
static char* twin_desired_property = "desired";

static char* twin_property_manufacturer_name = "manufacturer";
static char* twin_property_manufacturer_make_name = "make";
static char* twin_property_manufacturer_model_name = "model";
static char* twin_property_manufacturer_year_name = "year";
static char* twin_property_state_name = "state";
static char* twin_property_state_allowed_max_speed_name = "allowed_max_speed";
static char* twin_property_state_software_version_name = "software_version";
static char* twin_property_state_vanity_plate_name = "vanity_plate";
static char* twin_property_change_oil_reminder_name = "change_oil_reminder";
static char* twin_property_last_oil_change_date_name = "last_oil_change_date";

typedef struct MANUFACTURER_TAG
{
    char* make;                 // reported property
    char* model;                // reported property
    uint64_t year;              // reported property
} MANUFACTURER;

typedef struct STATE_TAG
{
    uint64_t allowed_max_speed; // desired/reported property
    double software_version;    // desired/reported property
    char* vanity_plate;         // reported property
} STATE;

typedef struct CAR_TAG
{
    bool change_oil_reminder;   // desired/reported property
    char* last_oil_change_date; // reported property
    MANUFACTURER manufacturer;  // reported property
    STATE state;                // desired/reported property
} CAR;

static CAR device_car = { .change_oil_reminder = false,
                          .last_oil_change_date = "May 4, 2016",
                          .manufacturer = { .make = "Fabrikam",
                                            .model = "sedan",
                                            .year = 2014 },
                          .state = { .allowed_max_speed = 100,
                                     .software_version = 1.1,
                                     .vanity_plate = "1T1" } };

// Functions
static void create_and_configure_device_client(void);
static void connect_device_client_send_and_receive_messages(void);
static void disconnect_device_client(void);

static void send_telemetry(void);
static void update_properties(CAR* new_car);
static void send_reported_property();
static void connection_status_callback(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void* user_context);
static void get_twin_async_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback);
static void twin_desired_properties_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback);
static void twin_reported_properties_callback(int status_code, void* userContextCallback);
static void send_telemetry_confirm_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback);
static IOTHUBMESSAGE_DISPOSITION_RESULT receive_c2d_message_callback(IOTHUB_MESSAGE_HANDLE message, void* user_context);
static bool parse_cbor_desired_property(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, CAR* out_car);
static void build_cbor_reported_property(uint8_t* reported_property_payload, size_t reported_property_payload_size, size_t* out_reported_property_payload_length);
static void build_cbor_telemetry(uint8_t* telemetry_payload, size_t telemetry_payload_size, size_t* out_telemetry_payload_length);


/*
 * This sample utilizes the Azure IoT Hub to get the device twin document, send a reported
 * property message, and receive desired property messages all in CBOR data format. It also shows
 * how to set the content type system property for C2D and telemetry messaging. After 10 attempts to
 * receive a C2D or desired property message, the sample will exit.
 *
 * To run this sample, Intel's MIT licensed TinyCBOR library must be installed. The Azure IoT C SDK
 * is not dependent on any particular CBOR library. SAS authentication is used.
 *
 * Device Twin:
 * There are three desired properties supported for this sample: `change_oil_reminder`,
 * `state.allowed_max_speed`, and `state.software_version`. To send a device twin desired property
 * message, select your device's Device Twin tab in the Azure Portal of your IoT Hub. Add one of the
 * available desired properties along with a corresponding value of the supported value type to the
 * `desired` section of the twin JSON. Select Save to update the twin document and send the twin
 * message to the device. The IoT Hub will translate the twin JSON into CBOR for the device to
 * consume and decode.
 *
 * "properties": {
 *     "desired": {
 *         "change_oil_reminder": true,
 *         "state": {
 *             "allowed_max_speed": 200,
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
 * NOTE: The Azure Portal only recognizes printable character input and will NOT translate a JSON
 * formatted message into CBOR. Therefore, this sample only demonstrates how to parse the topic for
 * the content type system property. It is up to the service application to encode correctly
 * formatted CBOR (or other specified content type) and the device application to correctly decode
 * it.
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
    // Send and receive messages from IoT Hub. Connection occurs when a message is first sent.
    //

    // Set callback for connection status to IoT Hub.
    rc = IoTHubDeviceClient_SetConnectionStatusCallback(iothub_client_handle, connection_status_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set the connection status callback: return code %d.\n", rc);
        exit(rc);
    }

    // Set callback for GET twin document request.
    // Send asynchronous GET request for twin document. Connection will occur here.
    rc = IoTHubDeviceClient_GetTwinAsync(iothub_client_handle, get_twin_async_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to send a GET request for the twin document asynchronously: return code %d.\n", rc);
        exit(rc);
    }

    // Set callback for twin desired property PATCH messages from IoT Hub.
    // Sends GET request for twin document as part of setting the callback.
    rc = IoTHubDeviceClient_SetDeviceTwinCallback(iothub_client_handle, twin_desired_properties_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set the twin document callback: return code %d.\n", rc);
        exit(rc);
    }

    // Set callback for C2D messages from the service client application.
    rc = IoTHubDeviceClient_SetMessageCallback(iothub_client_handle, receive_c2d_message_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set the C2D message callback: return code %d.\n", rc);
        exit(rc);
    }

    // Wait for desired property PATCH messages or C2D messages. Send Telemetry.
    for (uint8_t message_count = 0; message_count < MAX_MESSAGE_COUNT; message_count++)
    {
        ThreadAPI_Sleep(TIMEOUT_RECEIVE_MS);
        send_telemetry();
    }
}

static void disconnect_device_client(void)
{
    IoTHubDeviceClient_Destroy(iothub_client_handle);
    IoTHub_Deinit();
}

static void send_telemetry(void)
{
    int rc;

    // Build the telemetry message in CBOR.
    uint8_t telemetry_payload_buffer[TELEMETRY_MESSAGE_BUFFER_SIZE];
    size_t telemetry_payload_length;
    build_cbor_telemetry(
        telemetry_payload_buffer, sizeof(telemetry_payload_buffer), &telemetry_payload_length);
    message_handle = IoTHubMessage_CreateFromByteArray(telemetry_payload_buffer, telemetry_payload_length);

    // Set the content type system property value for telemetry messages. This value is
    // application-defined and must reflect what the service application expects.
    rc = IoTHubMessage_SetContentTypeSystemProperty(message_handle, CONTENT_TYPE_TELEMETRY);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set message properties content type for telemetry: return code %d.\n", rc);
        exit(rc);
    }

    (void)printf("\ntelemetry message payload: ");
    for (size_t i = 0; i < telemetry_payload_length; ++i)
    {
        (void)printf("%02X ", telemetry_payload_buffer[i]);
    }
    (void)printf("\n");

    // Publish the telemetry message. Set callback for telemetry send confirmation.
    uint64_t id = telemetry_message_id;
    IoTHubDeviceClient_SendEventAsync(iothub_client_handle, message_handle, send_telemetry_confirm_callback, &id);
    (void)printf("The device client published the telemetry message. telemetry_message_id: %" PRIu64 ".\n\n", id);

    // The message is copied to the SDK so we can destroy it.
    IoTHubMessage_Destroy(message_handle);
    telemetry_message_id++; // Increase for next telemetry message.
}


static void update_properties(CAR* new_car)
{
    // Update device_car from twin desired properties received from IoT Hub.
    // change_oil_reminder
    {
        bool old_value = device_car.change_oil_reminder;
        device_car.change_oil_reminder = new_car->change_oil_reminder;
        (void)printf("The device client updated `%s` locally from %s to %s.\n", twin_property_change_oil_reminder_name, old_value ? "true" : "false", device_car.change_oil_reminder ? "true" : "false");
    }

    // state.allowed_max_speed
    if (new_car->state.allowed_max_speed == 0)
    {
        (void)printf("`allowed_max_speed` cannot be 0. Rejecting update.\n");
    }
    else
    {
        if (new_car->state.allowed_max_speed > CAR_MAX_SPEED)
        {
            (void)printf("Desired `allowed_max_speed` of %" PRIu64 " exceeds device capability. Rejecting update.\n", new_car->state.allowed_max_speed);
        }
        else
        {
            uint64_t old_value = device_car.state.allowed_max_speed;
            device_car.state.allowed_max_speed = new_car->state.allowed_max_speed;
            (void)printf("The device client updated `%s` locally from %" PRIu64 " to %" PRIu64 ".\n", twin_property_state_allowed_max_speed_name, old_value, new_car->state.allowed_max_speed);
        }
    }

    // state.software_version
    if (new_car->state.software_version <= 0)
    {
        (void)printf("`software_version` cannot be 0.0 or negative. Rejecting update.\n");
    }
    else
    {
        double old_value = device_car.state.software_version;
        device_car.state.software_version = new_car->state.software_version;
        (void)printf("The device client updated `%s` locally from %.*f to %.*f.\n", twin_property_state_software_version_name, 1, old_value, 1, new_car->state.software_version);
    }
}

static void send_reported_property()
{
    // Send reported properties to IoT Hub.
    (void)printf("Reporting properties to IoT Hub.\n");
    build_cbor_reported_property(reported_property_buffer, REPORTED_PROPERTY_BUFFER_SIZE, &reported_property_length);
    int rc = IoTHubDeviceClient_SendReportedState(iothub_client_handle, reported_property_buffer, reported_property_length, twin_reported_properties_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to send a reported property PATCH request to the IoT Hub: return code %d.\n", rc);
        exit(rc);
    }
}

//
// Callbacks
//
static void connection_status_callback(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void* user_context)
{
    (void)reason;
    (void)user_context;

    if (result == IOTHUB_CLIENT_CONNECTION_AUTHENTICATED)
    {
        (void)printf("\nconnection_status_callback: The device client is connected to an IoT Hub.\n\n");
    }
    else
    {
        (void)printf("\nconnection_status_callback: The device client has been disconnected.\n\n");
    }
}

static void get_twin_async_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback)
{
    (void)userContextCallback;

    (void)printf("\nget_twin_async_callback payload: ");
    for (size_t i = 0; i < size; ++i)
    {
        (void)printf("%02X ", payload[i]);
    }
    (void)printf("\n");

    // Parse the twin desired properties received from IoT Hub.
    CAR iot_hub_car;
    memset(&iot_hub_car, 0, sizeof(CAR));
    if (parse_cbor_desired_property(update_state, payload, &iot_hub_car))
    {
        update_properties(&iot_hub_car);
    }

    send_reported_property();

    (void)printf("\n"); // Formatting
}

static void twin_desired_properties_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback)
{
    (void)userContextCallback;

    (void)printf("\ntwin_desired_properties_callback payload: ");
    for (size_t i = 0; i < size; ++i)
    {
        (void)printf("%02X ", payload[i]);
    }
    (void)printf("\n");

    // Parse the twin desired properties received from IoT Hub.
    CAR iot_hub_car;
    memset(&iot_hub_car, 0, sizeof(CAR));
    if (parse_cbor_desired_property(update_state, payload, &iot_hub_car))
    {
        update_properties(&iot_hub_car);
        send_reported_property();
    }

    (void)printf("\n"); // Formatting
}

static void twin_reported_properties_callback(int status_code, void* userContextCallback)
{
    (void)userContextCallback;
    (void)printf("\ntwin_reported_properties_callback: Result status code: %d\n\n", status_code);
}

static void send_telemetry_confirm_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback)
{
    uint64_t* id = (uint64_t*)userContextCallback;
    (void)printf("\nsend_telemetry_confirm_callback: telemetry_message_id: %" PRIu64 ", Result %s\n\n", *id, MU_ENUM_TO_STRING(IOTHUB_CLIENT_CONFIRMATION_RESULT, result));
}

static IOTHUBMESSAGE_DISPOSITION_RESULT receive_c2d_message_callback(IOTHUB_MESSAGE_HANDLE message, void* user_context)
{
    (void)user_context;

    const char* content_type = IoTHubMessage_GetContentTypeSystemProperty(message);
    if (content_type == NULL)
    {
        (void)printf("Content type system property could not be found in topic.\n");
    }
    else
    {
        // The content type system property value is application-defined and must reflect how the
        // service application has chosen to define it.
        if (strncmp(content_type, CONTENT_TYPE_C2D, strlen(CONTENT_TYPE_C2D)) == 0)
        {
            (void)printf("The device client received expected system property content type value: %s.\n", CONTENT_TYPE_C2D);

            // This content-type refers to how the message was created on the service-client application:
            // either from a byte array or a string. This sample assumes a byte array was used.
            IOTHUBMESSAGE_CONTENT_TYPE message_content_type = IoTHubMessage_GetContentType(message);
            if (message_content_type == IOTHUBMESSAGE_BYTEARRAY)
            {
                const unsigned char* payload;
                size_t payload_length;

                if (IoTHubMessage_GetByteArray(message, &payload, &payload_length) != IOTHUB_MESSAGE_OK)
                {
                    (void)printf("Failed to retrieve message as a byte array.\n");
                }
                else
                {
                    (void)printf("The device client retrieved the message as a byte array.\n");
                    // The application should parse the payload as the expected content type.
                }
            }
        }
        else
        {
            (void)printf("The device client did not receive expected system property content type value: %s.\n", CONTENT_TYPE_C2D);
        }
    }

    (void)printf("\n"); // Formatting

    return IOTHUBMESSAGE_ACCEPTED;
}

//
// Encoding/Decoding with CBOR library
//
static bool parse_cbor_desired_property(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, CAR* out_car)
{
    CborError rc; // CborNoError == 0
    bool result = false;

    CborParser parser;
    CborValue root;
    CborValue state_root;

    CborValue change_oil_reminder;
    CborValue allowed_max_speed;
    CborValue software_version;

    rc = cbor_parser_init(payload, strlen((char*)payload), 0, &parser, &root);
    if (rc)
    {
        (void)printf("Failed to initiate parser: CborError %d.\n", rc);
        exit(rc);
    }

    // Check if this is the full twin document or only the desired properties.
    if (update_state == DEVICE_TWIN_UPDATE_COMPLETE) // full twin document (desired and reported)
    {
        rc = cbor_value_map_find_value(&root, twin_desired_property, &root);
        if (rc)
        {
            (void)printf("Error when searching for %s: CborError %d.\n", twin_desired_property, rc);
            exit(rc);
        }
    }

    // change_oil_reminder
    rc = cbor_value_map_find_value(&root, twin_property_change_oil_reminder_name, &change_oil_reminder);
    if (rc)
    {
        (void)printf("Error when searching for %s: CborError %d.\n", twin_property_change_oil_reminder_name, rc);
        exit(rc);
    }
    if (cbor_value_is_valid(&change_oil_reminder))
    {
        if (cbor_value_is_boolean(&change_oil_reminder))
        {
            rc = cbor_value_get_boolean(&change_oil_reminder, &out_car->change_oil_reminder);
            if (rc)
            {
                (void)printf("Failed to get boolean value of property %s: CborError %d.\n", twin_property_change_oil_reminder_name, rc);
                exit(rc);
            }
            else
            {
                (void)printf("Parsed desired property `%s`: %s\n", twin_property_change_oil_reminder_name, out_car->change_oil_reminder ? "true" : "false");
                result = true;
            }
        }
        else
        {
            (void)printf("`%s` property value was not a boolean.\n", twin_property_change_oil_reminder_name);
        }
    }
    else
    {
        (void)printf("`%s` property name was not found in desired property message.\n", twin_property_change_oil_reminder_name);
    }

    // state
    rc = cbor_value_map_find_value(&root, twin_property_state_name, &state_root);
    if (rc)
    {
        (void)printf("Error when searching for %s: CborError %d.\n", twin_property_state_name, rc);
        exit(rc);
    }
    if (cbor_value_is_valid(&state_root))
    {
        // state.allowed_max_speed
        rc = cbor_value_map_find_value(&state_root, twin_property_state_allowed_max_speed_name, &allowed_max_speed);
        if (rc)
        {
            (void)printf("Error when searching for %s: CborError %d.\n", twin_property_state_allowed_max_speed_name, rc);
            exit(rc);
        }
        if (cbor_value_is_valid(&allowed_max_speed))
        {
            if (cbor_value_is_unsigned_integer(&allowed_max_speed))
            {
                rc = cbor_value_get_uint64(&allowed_max_speed, &out_car->state.allowed_max_speed);
                if (rc)
                {
                    (void)printf("Failed to get uint64 value of property %s: CborError %d.\n", twin_property_state_allowed_max_speed_name, rc);
                    exit(rc);
                }
                else
                {
                    (void)printf("Parsed desired property `%s`: %" PRIu64 "\n", twin_property_state_allowed_max_speed_name, out_car->state.allowed_max_speed);
                    result = true;
                }
            }
            else
            {
                (void)printf("`%s` property value was not an unsigned integer.\n", twin_property_state_allowed_max_speed_name);
            }
        }
        else
        {
            (void)printf("`%s` property name was not found in desired property message.\n", twin_property_state_allowed_max_speed_name);
        }

        // state.software_version
        rc = cbor_value_map_find_value(&state_root, twin_property_state_software_version_name, &software_version);
        if (rc)
        {
            (void)printf("Error when searching for %s: CborError %d.\n", twin_property_state_software_version_name, rc);
            exit(rc);
        }
        if (cbor_value_is_valid(&software_version))
        {
            if (cbor_value_is_double(&software_version))
            {
                rc = cbor_value_get_double(&software_version, &out_car->state.software_version);
                if (rc)
                {
                    (void)printf("Failed to get double value of property %s: CborError %d.\n", twin_property_state_software_version_name, rc);
                    exit(rc);
                }
                else
                {
                    (void)printf("Parsed desired property `%s`: %.*f\n", twin_property_state_software_version_name, 1, out_car->state.software_version);
                    result = true;
                }
            }
            else
            {
                (void)printf("`%s` property value was not a double.\n", twin_property_state_software_version_name);
            }
        }
        else
        {
            (void)printf("`%s` property name was not found in desired property message.\n", twin_property_state_software_version_name);
        }
    }
    else
    {
        (void)printf("`%s` property name was not found in desired property message.\n", twin_property_state_name);
    }

    return result;
}

static void build_cbor_reported_property(uint8_t* reported_property_payload, size_t reported_property_payload_size, size_t* out_reported_property_payload_length)
{
    CborError rc; // CborNoError == 0

    CborEncoder encoder;
    CborEncoder encoder_map;
    CborEncoder manufacturer_map;
    CborEncoder state_map;

    cbor_encoder_init(&encoder, reported_property_payload, reported_property_payload_size, 0);

    // Encoder Map
    rc = cbor_encoder_create_map(&encoder, &encoder_map, 4);
    if (rc)
    {
        (void)printf("Failed to create encoder map: CborError %d.\n", rc);
        exit(rc);
    }

        // change_oil_reminder
        rc = cbor_encode_text_string(&encoder_map, twin_property_change_oil_reminder_name, strlen(twin_property_change_oil_reminder_name));
        if (rc)
        {
            (void)printf("Failed to encode text string '%s': CborError %d.\n", twin_property_change_oil_reminder_name, rc);
            exit(rc);
        }
        rc = cbor_encode_boolean(&encoder_map, device_car.change_oil_reminder);
        if (rc)
        {
            (void)printf("Failed to encode boolean value '%s': CborError %d.\n", device_car.change_oil_reminder ? "true" : "false", rc);
            exit(rc);
        }

        // last_oil_change_date
        rc = cbor_encode_text_string(&encoder_map, twin_property_last_oil_change_date_name, strlen(twin_property_last_oil_change_date_name));
        if (rc)
        {
            (void)printf("Failed to encode text string '%s': CborError %d.\n", twin_property_last_oil_change_date_name, rc);
            exit(rc);
        }
        rc = cbor_encode_text_string(&encoder_map, device_car.last_oil_change_date, strlen(device_car.last_oil_change_date));
        if (rc)
        {
            (void)printf("Failed to encode text string '%s': CborError %d.\n", device_car.last_oil_change_date, rc);
            exit(rc);
        }

        // Manufacturer Map
        rc = cbor_encode_text_string(&encoder_map, twin_property_manufacturer_name, strlen(twin_property_manufacturer_name));
        if (rc)
        {
            (void)printf("Failed to encode text string '%s': CborError %d.\n", twin_property_manufacturer_name, rc);
            exit(rc);
        }
        rc = cbor_encoder_create_map(&encoder_map, &manufacturer_map, 3);
        if (rc)
        {
            (void)printf("Failed to create %s map: CborError %d.\n", twin_property_manufacturer_name, rc);
            exit(rc);
        }

            // manufacturer.make
            rc = cbor_encode_text_string(&manufacturer_map, twin_property_manufacturer_make_name, strlen(twin_property_manufacturer_make_name));
            if (rc)
            {
                (void)printf("Failed to encode text string '%s': CborError %d.\n", twin_property_manufacturer_make_name, rc);
                exit(rc);
            }
            rc = cbor_encode_text_string(&manufacturer_map, device_car.manufacturer.make, strlen(device_car.manufacturer.make));
            if (rc)
            {
                (void)printf("Failed to encode text string '%s': CborError %d.\n",  device_car.manufacturer.make, rc);
                exit(rc);
            }

            // manufacturer.model
            rc = cbor_encode_text_string(&manufacturer_map, twin_property_manufacturer_model_name, strlen(twin_property_manufacturer_model_name));
            if (rc)
            {
                (void)printf("Failed to encode text string '%s': CborError %d.\n", twin_property_manufacturer_model_name, rc);
                exit(rc);
            }
            rc = cbor_encode_text_string(&manufacturer_map, device_car.manufacturer.model, strlen(device_car.manufacturer.model));
            if (rc)
            {
                (void)printf("Failed to encode text string '%s': CborError %d.\n",  device_car.manufacturer.model, rc);
                exit(rc);
            }

            // manufacturer.year
            rc = cbor_encode_text_string(&manufacturer_map, twin_property_manufacturer_year_name, strlen(twin_property_manufacturer_year_name));
            if (rc)
            {
                (void)printf("Failed to encode text string '%s': CborError %d.\n", twin_property_manufacturer_year_name, rc);
                exit(rc);
            }
            rc = cbor_encode_uint(&manufacturer_map, device_car.manufacturer.year);
            if (rc)
            {
                (void)printf("Failed to encode int '%" PRIu64 "': CborError %d.\n", device_car.manufacturer.year, rc);
                exit(rc);
            }

        rc = cbor_encoder_close_container(&encoder_map, &manufacturer_map);
        if (rc)
        {
            (void)printf("Failed to close %s container: CborError %d.\n", twin_property_manufacturer_name, rc);
            exit(rc);
        }

        // State Map
        rc = cbor_encode_text_string(&encoder_map, twin_property_state_name, strlen(twin_property_state_name));
        if (rc)
        {
            (void)printf("Failed to encode text string '%s': CborError %d.\n", twin_property_state_name, rc);
            exit(rc);
        }
        rc = cbor_encoder_create_map(&encoder_map, &state_map, 3);
        if (rc)
        {
            (void)printf("Failed to create %s map: CborError %d.\n", twin_property_state_name, rc);
            exit(rc);
        }

            // state.allowed_max_speed
            rc = cbor_encode_text_string(&state_map, twin_property_state_allowed_max_speed_name, strlen(twin_property_state_allowed_max_speed_name));
            if (rc)
            {
                (void)printf("Failed to encode text string '%s': CborError %d.\n", twin_property_state_allowed_max_speed_name, rc);
                exit(rc);
            }
            rc = cbor_encode_uint(&state_map, device_car.state.allowed_max_speed);
            if (rc)
            {
                (void)printf("Failed to encode int '%" PRIu64 "': CborError %d.\n", device_car.state.allowed_max_speed, rc);
                exit(rc);
            }

            // state.software_version
            rc = cbor_encode_text_string(&state_map, twin_property_state_software_version_name, strlen(twin_property_state_software_version_name));
            if (rc)
            {
                (void)printf("Failed to encode text string '%s': CborError %d.\n", twin_property_state_software_version_name, rc);
                exit(rc);
            }
            rc = cbor_encode_double(&state_map, device_car.state.software_version);
            if (rc)
            {
                (void)printf("Failed to encode double '%.*f': CborError %d.\n", 1, device_car.state.software_version, rc);
                exit(rc);
            }

            // state.vanity_plate
            rc = cbor_encode_text_string(&state_map, twin_property_state_vanity_plate_name, strlen(twin_property_state_vanity_plate_name));
            if (rc)
            {
                (void)printf("Failed to encode text string '%s': CborError %d.\n", twin_property_state_vanity_plate_name, rc);
                exit(rc);
            }
            rc = cbor_encode_text_string(&state_map, device_car.state.vanity_plate, strlen(device_car.state.vanity_plate));
            if (rc)
            {
                (void)printf("Failed to encode text string '%s': CborError %d.\n",  device_car.state.vanity_plate, rc);
                exit(rc);
            }

        rc = cbor_encoder_close_container(&encoder_map, &state_map);
        if (rc)
        {
            (void)printf("Failed to close %s container: CborError %d.\n", twin_property_state_name, rc);
            exit(rc);
        }

    rc = cbor_encoder_close_container(&encoder, &encoder_map);
    if (rc)
    {
        (void)printf("Failed to close container: CborError %d.\n", rc);
        exit(rc);
    }

    *out_reported_property_payload_length = cbor_encoder_get_buffer_size(&encoder, reported_property_payload);
}

static void build_cbor_telemetry(uint8_t* telemetry_payload, size_t telemetry_payload_size, size_t* out_telemetry_payload_length)
{
    float engine_temperature = 200.0f + ((float)rand() / RAND_MAX) * 5.0f;

    CborError rc; // CborNoError == 0

    CborEncoder encoder;
    CborEncoder encoder_map;

    cbor_encoder_init(&encoder, telemetry_payload, telemetry_payload_size, 0);

    rc = cbor_encoder_create_map(&encoder, &encoder_map, 1);
    if (rc)
    {
        (void)printf("Failed to create map: CborError %d.", rc);
        exit(rc);
    }

    rc = cbor_encode_text_string(
        &encoder_map, telemetry_property_engine_temperature_name, strlen(telemetry_property_engine_temperature_name));
    if (rc)
    {
        (void)printf("Failed to encode text string '%s': CborError %d.", telemetry_property_engine_temperature_name, rc);
        exit(rc);
    }

    rc = cbor_encode_double(&encoder_map, engine_temperature);
    if (rc)
    {
        (void)printf("Failed to encode double '%.*f': CborError %d.", 2, engine_temperature, rc);
        exit(rc);
    }

    rc = cbor_encoder_close_container(&encoder, &encoder_map);
    if (rc)
    {
        (void)printf("Failed to close container: CborError %d.", rc);
        exit(rc);
    }

    *out_telemetry_payload_length = cbor_encoder_get_buffer_size(&encoder, telemetry_payload);
}
