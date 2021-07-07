// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This sample shows how to translate the Device Twin json received from Azure IoT Hub into meaningful data for your application.
// It uses the parson library, a very lightweight json parser.

// There is an analogous sample using the serializer - which is a library provided by this SDK to help parse json - in devicetwin_simplesample.
// Most applications should use this sample, not the serializer.

// WARNING: Check the return of all API calls when developing your solution. Return checks ommited for sample simplification.

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "azure_macro_utils/macro_utils.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/platform.h"
#include "iothub_device_client.h"
#include "iothub_client_options.h"
#include "iothub.h"
#include "iothub_twin.h"
#include "parson.h"

#define MAX_MESSAGE_COUNT 20
#define TIMEOUT_SEND_GET_REQUEST_MS (60 * 1000)
#define TIMEOUT_RECEIVE_MS (30 * 1000)

#define CAR_MAX_SPEED 260

// Trusted Cert -- Turn on via build flag
#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    #include "certs.h"
#endif

// Transport Layer Protocol -- Uncomment the protocol you wish to use.
#define SAMPLE_MQTT
//#define SAMPLE_MQTT_OVER_WEBSOCKETS
//#define SAMPLE_AMQP
//#define SAMPLE_AMQP_OVER_WEBSOCKETS
//#define SAMPLE_HTTP

#ifdef SAMPLE_MQTT
    #include "iothubtransportmqtt.h"
    static IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = MQTT_Protocol;
#elif defined SAMPLE_MQTT_OVER_WEBSOCKETS
    #include "iothubtransportmqtt_websockets.h"
    static IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = MQTT_WebSocket_Protocol;
#elif defined SAMPLE_AMQP
    #include "iothubtransportamqp.h"
    static IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = AMQP_Protocol;
#elif defined SAMPLE_AMQP_OVER_WEBSOCKETS
    #include "iothubtransportamqp_websockets.h"
    static IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = AMQP_Protocol_over_WebSocketTls;
#elif defined SAMPLE_HTTP
    #include "iothubtransporthttp.h"
    static IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = HTTP_Protocol;
#endif

// Connection String -- Paste in the iothub device connection string.
static const char* connection_string = "[device connections string]";

static IOTHUB_DEVICE_CLIENT_HANDLE iothub_client;
static IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE twin_request_options;

static bool message_received = false;
static int64_t twin_property_desired_version_value = 0;

// Device Twin Properties
#define TWIN_DESIRED "desired"
#define TWIN_VERSION "$version"
#define TWIN_MANUFACTURER "manufacturer"
#define TWIN_MAKE "make"
#define TWIN_MODEL "model"
#define TWIN_YEAR "year"
#define TWIN_STATE "state"
#define TWIN_ALLOWED_MAX_SPEED "allowed_max_speed"
#define TWIN_SOFTWARE_VERSION "software_version"
#define TWIN_VANITY_PLATE "vanity_plate"
#define TWIN_CHANGE_OIL_REMINDER "change_oil_reminder"
#define TWIN_LAST_OIL_CHANGE_DATE "last_oil_change_date"

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

static void update_properties(CAR* new_car);
static void send_reported_property();
static void connection_status_callback(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void* user_context);
static void get_twin_async_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* user_context);
#if defined SAMPLE_MQTT || defined SAMPLE_MQTT_OVER_WEBSOCKETS
static void get_twin_desired_properties_async_callback(DEVICE_TWIN_UPDATE_STATE update_state, IOTHUB_TWIN_RESPONSE_HANDLE twin_response, const unsigned char* payload, size_t size, void* user_context);
#endif
static void patch_twin_desired_properties_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* user_context);
static void patch_twin_reported_properties_callback(int status_code, void* user_context);
static int receive_method_callback(const char* method_name, unsigned char const* payload, size_t size, unsigned char** response, size_t* response_size, void* user_context);
static bool parse_twin_document(const unsigned char* payload, CAR* out_car, int64_t* out_parsed_desired_version);
static bool parse_twin_document_desired(const unsigned char* payload, CAR* out_car);
static bool parse_desired_patch(const unsigned char* payload, CAR* out_car, int64_t* out_parsed_desired_version);
static char* malloc_and_build_json_reported_property(void);

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

    iothub_client = IoTHubDeviceClient_CreateFromConnectionString(connection_string, protocol);
    if (iothub_client == NULL)
    {
        (void)printf("Failed to create device client from connection string.\n");
        exit(EXIT_FAILURE);
    }

#if defined SAMPLE_MQTT || defined SAMPLE_MQTT_OVER_WEBSOCKETS
    twin_request_options = IoTHubTwin_CreateRequestOptions();
    if (twin_request_options == NULL)
    {
        (void)printf("Failed to create twin request options.\n");
        exit(EXIT_FAILURE);
    }
#endif

    //
    // Set Options
    //
    bool trace_on = true; // Debugging
    rc = IoTHubDeviceClient_SetOption(iothub_client, OPTION_LOG_TRACE, &trace_on);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set option for %s: return code %d.\n", OPTION_LOG_TRACE, rc);
        exit(rc);
    }

#if defined SAMPLE_MQTT || defined SAMPLE_MQTT_OVER_WEBSOCKETS
    // Set the auto URL Encoder (recommended for MQTT). Please use this option unless you are URL
    // Encoding inputs yourself. ONLY valid for use with MQTT.
    bool url_encode_on = true;
    rc = IoTHubDeviceClient_SetOption(iothub_client, OPTION_AUTO_URL_ENCODE_DECODE, &url_encode_on);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set option for %s: return code %d.\n", OPTION_AUTO_URL_ENCODE_DECODE, rc);
        exit(rc);
    }
#endif

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    // Use SDK-supplied trusted certificates to run the sample.
    // ONLY to be used for the sample. **NOT to be used in production code.**
    rc = IoTHubDeviceClient_SetOption(iothub_client, OPTION_TRUSTED_CERT, certificates);
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
    rc = IoTHubDeviceClient_SetConnectionStatusCallback(iothub_client, connection_status_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set the connection status callback: return code %d.\n", rc);
        exit(rc);
    }

    // Set callback for GET twin document request.
    // Send asynchronous GET request for twin document. Connection will occur here.
    rc = IoTHubDeviceClient_GetTwinAsync(iothub_client, get_twin_async_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to send a GET request for the twin document asynchronously: return code %d.\n", rc);
        exit(rc);
    }

    // Set callback for twin desired property PATCH messages from IoT Hub.
    // Sends GET request for twin document as part of setting the callback.
    rc = IoTHubDeviceClient_SetDeviceTwinCallback(iothub_client, patch_twin_desired_properties_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set the twin document callback: return code %d.\n", rc);
        exit(rc);
    }

    // Set callback for C2D direct methods from the service client application.
    rc = IoTHubDeviceClient_SetDeviceMethodCallback(iothub_client, receive_method_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to set the C2D method callback: return code %d.\n", rc);
        exit(rc);
    }

    // Wait for twin` GET response, a reported property PATCH response, a desired property PATCH
    // message, or a direct method. Returns if timeout occurs. After TIMEOUT_SEND_GET_REQUEST_MS
    // seconds, request the twin document's desired properties.
    time_t receive_message_start_time = time(NULL);
#if defined SAMPLE_MQTT || defined SAMPLE_MQTT_OVER_WEBSOCKETS
    time_t send_get_request_start_time = time(NULL);
#endif
    time_t current_time;
    message_received = false;

    for (uint8_t message_count = 0; message_count < MAX_MESSAGE_COUNT; message_count++)
    {
        // Wait up to TIMEOUT_RECEIVE_MS to receive a message.
        while(1)
        {
            if (message_received)
            {
                receive_message_start_time = time(NULL);
                message_received = false;
                break;
            }

            current_time = time(NULL);
            if ((1000 * (current_time - receive_message_start_time)) >= TIMEOUT_RECEIVE_MS)
            {
                printf("Receive message timeout expired.\n");
                receive_message_start_time = time(NULL);
                message_received = false;
                break;
            }
        }

#if defined SAMPLE_MQTT || defined SAMPLE_MQTT_OVER_WEBSOCKETS
        // Send twin desired GET request if TIMEOUT_SEND_GET_REQUEST_MS expired.
        current_time = time(NULL);
        if ((1000 * (current_time - send_get_request_start_time)) >= TIMEOUT_SEND_GET_REQUEST_MS)
        {
            //By default, all options are "off". To turn an option "off" later, pass in  NULL.
            twin_request_options->set_current_version(twin_request_options, &twin_property_desired_version_value);
            rc = IoTHubDeviceClient_GetTwinDesiredAsync(iothub_client, twin_request_options, get_twin_desired_properties_async_callback, NULL);
            if (rc != IOTHUB_CLIENT_OK)
            {
                (void)printf("Failed to send a GET request for the twin document `desired` asynchronously: return code %d.\n", rc);
                exit(rc);
            }
            send_get_request_start_time = time(NULL);
        }
#endif
    }
}

static void disconnect_device_client(void)
{
    IoTHubDeviceClient_Destroy(iothub_client);
#if defined SAMPLE_MQTT || defined SAMPLE_MQTT_OVER_WEBSOCKETS
    IoTHubTwin_DestroyRequestOptions(twin_request_options);
#endif
    IoTHub_Deinit();
}

static void update_properties(CAR* new_car)
{
    // Update device_car from twin desired properties received from IoT Hub.
    // change_oil_reminder
    {
        (void)printf("Client updating `" TWIN_CHANGE_OIL_REMINDER "` locally from %s to %s.\n", device_car.change_oil_reminder ? "true" : "false", new_car->change_oil_reminder ? "true" : "false");
        device_car.change_oil_reminder = new_car->change_oil_reminder;
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
            (void)printf("Desired `" TWIN_ALLOWED_MAX_SPEED "` of %" PRIu64 " exceeds device capability. Rejecting update.\n", new_car->state.allowed_max_speed);
        }
        else
        {
            (void)printf("Client updating`" TWIN_ALLOWED_MAX_SPEED "` locally from %" PRIu64 " to %" PRIu64 ".\n", device_car.state.allowed_max_speed, new_car->state.allowed_max_speed);
            device_car.state.allowed_max_speed = new_car->state.allowed_max_speed;
        }
    }

    // state.software_version
    if (new_car->state.software_version <= 0)
    {
        (void)printf("`" TWIN_SOFTWARE_VERSION "` cannot be 0.0 or negative. Rejecting update.\n");
    }
    else
    {
        (void)printf("Client updating `" TWIN_SOFTWARE_VERSION "` locally from %.*f to %.*f.\n", 1, device_car.state.software_version, 1, new_car->state.software_version);
        device_car.state.software_version = new_car->state.software_version;
    }
}

static void send_reported_property()
{
    // Send reported properties to IoT Hub.
    (void)printf("Client reporting properties to IoT Hub.\n");
    char* reported_property = malloc_and_build_json_reported_property();
    int rc = IoTHubDeviceClient_SendReportedState(iothub_client, (const unsigned char*)reported_property, strlen(reported_property), patch_twin_reported_properties_callback, NULL);
    if (rc != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to send a reported property PATCH request to the IoT Hub: return code %d.\n", rc);
        exit(rc);
    }

    free(reported_property);
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

static void get_twin_async_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* user_context)
{
    if (update_state != DEVICE_TWIN_UPDATE_COMPLETE) // Twin document is ill-formed.
    {
        (void)printf("Payload does not contain a full twin document.");
        exit(EXIT_FAILURE);
    }

    (void)user_context;

    message_received = true;
    (void)printf("\nget_twin_async_callback payload: %.*s\n", (int32_t)size, payload);

    // No version for full GET twin. `$version` must be parsed from `desired` properties.
    int64_t parsed_desired_version;
    CAR iot_hub_car;
    memset(&iot_hub_car, 0, sizeof(CAR));

    if (parse_twin_document(payload, &iot_hub_car, &parsed_desired_version))
    {
        update_properties(&iot_hub_car);
    }
    (void)printf("Client updating desired `$version` locally from %ld to %ld.\n", twin_property_desired_version_value, parsed_desired_version);
    twin_property_desired_version_value = parsed_desired_version;

    send_reported_property();

    (void)printf("\n"); // Formatting
}

#if defined SAMPLE_MQTT || defined SAMPLE_MQTT_OVER_WEBSOCKETS
static void get_twin_desired_properties_async_callback(DEVICE_TWIN_UPDATE_STATE update_state, IOTHUB_TWIN_RESPONSE_HANDLE twin_response, const unsigned char* payload, size_t size, void* user_context)
{
    if (update_state != DEVICE_TWIN_UPDATE_PARTIAL) // Twin document is ill-formed.
    {
        (void)printf("Payload does not a twin desired document.\n");
        exit(EXIT_FAILURE);
    }

    (void)user_context;

    message_received = true;
    (void)printf("\nget_twin_desired_properties_async_callback payload: %.*s\n", (int32_t)size, payload);

    // Retrieve response status
    int64_t response_status;
    if (twin_response->get_status(twin_response, &response_status))
    {
        printf("Status: %ld\n", response_status);
    }
    else
    {
        (void)printf("Failed to retrieve status from response topic.\n");
        exit(EXIT_FAILURE);
    }

/* NOT YET IMPLEMENTED ON HUB
    // Retrieve response version
    int64_t response_version;
    if (twin_response->get_version(twin_response, &response_version))
    {
        (void)printf("Client updating desired `$version` locally from %ld to %ld.\n", twin_property_desired_version_value, response_version);
        twin_property_desired_version_value = response_version;
    }
    else
    {
        (void)printf("Failed to retrieve version from response topic.\n");
        //exit(EXIT_FAILURE);
    }
*/
    if (response_status == 200 || response_status == 202)
    {
        CAR iot_hub_car;
        memset(&iot_hub_car, 0, sizeof(CAR));
        if (parse_twin_document_desired(payload, &iot_hub_car))
        {
            update_properties(&iot_hub_car);
        }
        send_reported_property();
    }
    else if (response_status == 304) // No payload
    {
    /* NOT YET IMPLEMENTED ON HUB
        if (twin_property_desired_version_value != response_version)
        {
            printf("Twin desired versions unexpectedly do not match. Client's desired `$version`: %ld, IoT Hub desired `$version`: %ld\n",
                twin_property_desired_version_value, response_version);
            exit(EXIT_FAILURE);
        }
        printf("Twin desired versions match. Client's desired `$version`: %ld, IoT Hub desired `$version`: %ld.\n",
            twin_property_desired_version_value, response_version);
    */
        printf("Twin desired versions match. Client's desired `$version`: %ld.\n", twin_property_desired_version_value);
    }
    else
    {
        (void)printf("Response status value %ld unexpected.\n", response_status);
        exit(EXIT_FAILURE);
    }

    (void)printf("\n"); // Formatting
    return;
}
#endif

static void patch_twin_desired_properties_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* user_context)
{
    // This callback may receive full twin document in payload at subscription, or desired section in payload from server PATCH request.
    if (update_state != DEVICE_TWIN_UPDATE_PARTIAL)
    {
        // Ignore. Will parse Full twin payload response via GetTwinAsync callback.
        return;
    }

    (void)update_state;
    (void)user_context;

    message_received = true;
    (void)printf("\npatch_twin_desired_properties_callback payload: %.*s\n", (int32_t)size, payload);

    // Parse the twin desired properties received from IoT Hub.
    int64_t parsed_desired_version;
    CAR iot_hub_car;
    memset(&iot_hub_car, 0, sizeof(CAR));
    if (parse_desired_patch(payload, &iot_hub_car, &parsed_desired_version))
    {
        update_properties(&iot_hub_car);
    }
    (void)printf("Client updating desired `$version` locally from %ld to %ld.\n", twin_property_desired_version_value, parsed_desired_version);
    twin_property_desired_version_value = parsed_desired_version;

    send_reported_property();

    (void)printf("\n"); // Formatting
}

static void patch_twin_reported_properties_callback(int status_code, void* user_context)
{
    (void)user_context;

    message_received = true;
    (void)printf("\npatch_twin_reported_properties_callback: Result status code: %d\n\n", status_code);
}

static int receive_method_callback(char const* method_name, unsigned char const* payload, size_t size, unsigned char** response, size_t* response_size, void* user_context)
{
    (void)user_context;
    (void)payload;
    (void)size;

    int result;

     message_received = true;
    (void)printf("\nreceive_method_callback: method name: %s\n", method_name);

    if (strcmp("getCarVIN", method_name) == 0)
    {
        const char deviceMethodResponse[] = "{ \"Response\": \"1HGCM82633A004352\" }";
        *response_size = sizeof(deviceMethodResponse)-1;
        *response = malloc(*response_size);
        (void)memcpy(*response, deviceMethodResponse, *response_size);
        result = 200;
    }
    else
    {
        // All other entries are ignored.
        const char deviceMethodResponse[] = "{ }";
        *response_size = sizeof(deviceMethodResponse)-1;
        *response = malloc(*response_size);
        (void)memcpy(*response, deviceMethodResponse, *response_size);
        result = -1;
    }

    (void)printf("\n"); // Formatting

    return result;
}

//
// Encoding/Decoding with JSON library
//
static bool parse_twin_document(const unsigned char* payload, CAR* out_car, int64_t* out_parsed_desired_version)
{
    bool parsed = parse_twin_document_desired(payload, out_car);

    // For a GET full twin request, each section's $version may need to be parsed.
    if (out_parsed_desired_version)
    {
        JSON_Value* root_value = json_parse_string(payload);
        JSON_Object* root_object = json_value_get_object(root_value);

        char* version_name = TWIN_DESIRED "." TWIN_VERSION;
        double version = json_object_dotget_number(root_object, version_name);
        if (version != 0)
        {
            *out_parsed_desired_version = version;
            (void)printf("Parsed desired property `%s`: %ld\n", version_name, *out_parsed_desired_version);
        }
        else // Twin document is ill-formed.
        {
            (void)printf("Failed to parse for desired `%s` property.\n", version_name);
            exit(EXIT_FAILURE);
        }
    }

    return parsed;
}

static bool parse_twin_document_desired(const unsigned char* payload, CAR* out_car)
{
    bool result = false;

    JSON_Value* root_value = json_parse_string(payload);
    JSON_Object* root_object = json_value_get_object(root_value);

    int change_oil_reminder;
    double allowed_max_speed;
    double software_version;

    // NOTE: The response payload to a GET desired twin request will have the `desired` delimiter.
    char* change_oil_reminder_name = TWIN_DESIRED "." TWIN_CHANGE_OIL_REMINDER;
    char* allowed_max_speed_name = TWIN_DESIRED "." TWIN_STATE "." TWIN_ALLOWED_MAX_SPEED;
    char* software_version_name = TWIN_DESIRED "." TWIN_STATE "." TWIN_SOFTWARE_VERSION;

    change_oil_reminder = json_object_dotget_boolean(root_object, change_oil_reminder_name);
    if (change_oil_reminder != -1)
    {
        out_car->change_oil_reminder = change_oil_reminder;
        (void)printf("Parsed desired property `%s`: %s\n", change_oil_reminder_name, out_car->change_oil_reminder ? "true" : "false");
        result = true;
    }
    else
    {
        (void)printf("`%s` property was not found in desired property message.\n", change_oil_reminder_name);
    }

    allowed_max_speed = json_object_dotget_number(root_object, allowed_max_speed_name);
    if (allowed_max_speed != 0)
    {
        out_car->state.allowed_max_speed = allowed_max_speed;
        (void)printf("Parsed desired property `%s`: %" PRIu64 "\n", allowed_max_speed_name, (uint64_t)out_car->state.allowed_max_speed);
        result = true;
    }
    else
    {
        (void)printf("`%s` property was not found in desired property message.\n", allowed_max_speed_name);
    }

    software_version = json_object_dotget_number(root_object, software_version_name);
    if (software_version != 0)
    {
        out_car->state.software_version = software_version;
        (void)printf("Parsed desired property `%s`: %.*f\n", software_version_name, 1, out_car->state.software_version);
        result = true;
    }
    else
    {
        (void)printf("`%s` property was not found in desired property message.\n", software_version_name);
    }

    return result;
}

static bool parse_desired_patch(const unsigned char* payload, CAR* out_car, int64_t* out_parsed_desired_version)
{
    bool result = false;

    JSON_Value* root_value = json_parse_string(payload);
    JSON_Object* root_object = json_value_get_object(root_value);

    int change_oil_reminder;
    double allowed_max_speed;
    double software_version;

    // The PATCH desired message will not have the `desired` delimieter.
    char* change_oil_reminder_name = TWIN_CHANGE_OIL_REMINDER;
    char* allowed_max_speed_name = TWIN_STATE "." TWIN_ALLOWED_MAX_SPEED;
    char* software_version_name = TWIN_STATE "." TWIN_SOFTWARE_VERSION;

    change_oil_reminder = json_object_dotget_boolean(root_object, change_oil_reminder_name);
    if (change_oil_reminder != -1)
    {
        out_car->change_oil_reminder = change_oil_reminder;
        (void)printf("Parsed desired property `%s`: %s\n", change_oil_reminder_name, out_car->change_oil_reminder ? "true" : "false");
        result = true;
    }
    else
    {
        (void)printf("`%s` property was not found in desired property message.\n", change_oil_reminder_name);
    }

    allowed_max_speed = json_object_dotget_number(root_object, allowed_max_speed_name);
    if (allowed_max_speed != 0)
    {
        out_car->state.allowed_max_speed = allowed_max_speed;
        (void)printf("Parsed desired property `%s`: %" PRIu64 "\n", allowed_max_speed_name, (uint64_t)out_car->state.allowed_max_speed);
        result = true;
    }
    else
    {
        (void)printf("`%s` property was not found in desired property message.\n", allowed_max_speed_name);
    }

    software_version = json_object_dotget_number(root_object, software_version_name);
    if (software_version != 0)
    {
        out_car->state.software_version = software_version;
        (void)printf("Parsed desired property `%s`: %.*f\n", software_version_name, 1, out_car->state.software_version);
        result = true;
    }
    else
    {
        (void)printf("`%s` property was not found in desired property message.\n", software_version_name);
    }

    if (out_parsed_desired_version)
    {
        char* version_name = TWIN_VERSION;
        double version = json_object_dotget_number(root_object, version_name);
        if (version != 0)
        {
            *out_parsed_desired_version = version;
            (void)printf("Parsed desired property `%s`: %ld\n", version_name, *out_parsed_desired_version);
        }
        else // Twin document is ill-formed.
        {
            (void)printf("Failed to parse for desired `%s` property.\n", version_name);
            exit(EXIT_FAILURE);
        }
    }

    return result;
}

static char* malloc_and_build_json_reported_property(void)
{
    char* reported_properties_json;
    JSON_Status rc; // JSONSuccess == 0

    JSON_Value* root_value = json_value_init_object();
    JSON_Object* root_object = json_value_get_object(root_value);

    rc = json_object_set_boolean(root_object, TWIN_CHANGE_OIL_REMINDER, device_car.change_oil_reminder);
    if (rc)
    {
        (void)printf("Failed to encode boolean value '%s': JSON_Status %d.\n", device_car.change_oil_reminder ? "true" : "false", rc);
        exit(rc);
    }

    rc = json_object_set_string(root_object, TWIN_LAST_OIL_CHANGE_DATE, device_car.last_oil_change_date);
    if (rc)
    {
        (void)printf("Failed to encode text string '%s': JSON_Status %d.\n", device_car.last_oil_change_date, rc);
        exit(rc);
    }

    rc = json_object_dotset_string(root_object, TWIN_MANUFACTURER "." TWIN_MAKE, device_car.manufacturer.make);
    if (rc)
    {
        (void)printf("Failed to encode text string '%s': JSON_Status %d.\n", device_car.manufacturer.make, rc);
        exit(rc);
    }

    rc = json_object_dotset_string(root_object, TWIN_MANUFACTURER "." TWIN_MODEL, device_car.manufacturer.model);
    if (rc)
    {
        (void)printf("Failed to encode text string '%s': JSON_Status %d.\n", device_car.manufacturer.model, rc);
        exit(rc);
    }

    rc = json_object_dotset_number(root_object, TWIN_MANUFACTURER "." TWIN_YEAR, device_car.manufacturer.year);
    if (rc)
    {
        (void)printf("Failed to encode int '%" PRIu64 "': JSON_Status %d.\n", device_car.manufacturer.year, rc);
        exit(rc);
    }

    rc = json_object_dotset_number(root_object, TWIN_STATE "." TWIN_ALLOWED_MAX_SPEED, device_car.state.allowed_max_speed);
    if (rc)
    {
        (void)printf("Failed to encode int '%" PRIu64 "': JSON_Status %d.\n", device_car.state.allowed_max_speed, rc);
        exit(rc);
    }

    rc = json_object_dotset_number(root_object, TWIN_STATE "." TWIN_SOFTWARE_VERSION, device_car.state.software_version);
    if (rc)
    {
        (void)printf("Failed to encode double '%.*f': JSON_Status %d.\n", 1, device_car.state.software_version, rc);
        exit(rc);
    }

    rc = json_object_dotset_string(root_object, TWIN_STATE "." TWIN_VANITY_PLATE, device_car.state.vanity_plate);
    if (rc)
    {
        (void)printf("Failed to encode text string '%s': JSON_Status %d.\n", device_car.state.vanity_plate, rc);
        exit(rc);
    }

    reported_properties_json = json_serialize_to_string(root_value);

    json_value_free(root_value);

    return reported_properties_json;
}
