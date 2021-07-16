// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#endif

#include "azure_c_shared_utility/lock.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/uniqueid.h"
#include "azure_c_shared_utility/xlogging.h"

#include "iothub.h"
#include "iothub_account.h"
#include "iothub_client_options.h"
#include "iothub_device_client.h"
#include "iothub_devicetwin.h"
#include "iothub_module_client.h"
#include "iothubtest.h"
#include "parson.h"
#include "testrunnerswitcher.h"

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
#include "certs.h"
#endif // SET_TRUSTED_CERT_IN_SAMPLES

#define MAX_CLOUD_TRAVEL_TIME  120.0    /* 2 minutes */
#define BUFFER_SIZE            37
#define CBOR_STRING_BUFFER_SIZE       7

TEST_DEFINE_ENUM_TYPE(IOTHUB_CLIENT_RESULT, IOTHUB_CLIENT_RESULT_VALUES);
TEST_DEFINE_ENUM_TYPE(DEVICE_TWIN_UPDATE_STATE, DEVICE_TWIN_UPDATE_STATE_VALUES);

static IOTHUB_ACCOUNT_INFO_HANDLE iothub_accountinfo_handle = NULL;
static IOTHUB_DEVICE_CLIENT_HANDLE iothub_deviceclient_handle = NULL;
static IOTHUB_MODULE_CLIENT_HANDLE iothub_moduleclient_handle = NULL;

//
// Test structures and parsing functions
//
static int _generate_new_int(void)
{
    int return_value;
    time_t now_time = time(NULL);

    return_value = (int) now_time;
    return return_value;
}

static int8_t _generate_new_CBOR_int(void)
{
    // CBOR represents decimal 0 to 23 with one byte.
    // Decimal 24 and above requires an additional 'tag' byte.

    int8_t return_value;
    time_t now_time = time(NULL);

    return_value = (int8_t)(now_time % 24);
    return return_value;
}

static char* _generate_unique_string(void)
{
    char* return_value;

    return_value = (char*)malloc(BUFFER_SIZE);
    if (return_value == NULL)
    {
        LogError("malloc failed");
    }
    else if (UniqueId_Generate(return_value, BUFFER_SIZE) != UNIQUEID_OK)
    {
        LogError("UniqueId_Generate failed");
        free(return_value);
        return_value = NULL;
    }
    return return_value;
}

static uint8_t* _generate_unique_CBOR_string(void)
{
    // 0x67 tag byte, followed by 7 bytes representing UTF-8 encoded characters. Total 8 bytes.
    char* return_value;
    char temp_value[BUFFER_SIZE];

    return_value = (uint8_t*)malloc(CBOR_STRING_BUFFER_SIZE);

    if (return_value == NULL)
    {
        LogError("malloc failed");
    }
    else
    {
        if (UniqueId_Generate(temp_value, BUFFER_SIZE) != UNIQUEID_OK)
        {
            LogError("UniqueId_Generate failed");
            free(return_value);
            return_value = NULL;
        }
        else
        {
            memcpy(return_value, temp_value, CBOR_STRING_BUFFER_SIZE);
        }
    }
    return return_value;
}

typedef struct DEVICE_DESIRED_DATA_TAG
{
    bool received_callback;                     // true when device callback has been called
    DEVICE_TWIN_UPDATE_STATE update_state;      // status reported by the callback
    char* cb_payload;
    size_t cb_payload_size;
    LOCK_HANDLE lock;
} DEVICE_DESIRED_DATA;

static DEVICE_DESIRED_DATA* _device_desired_data_init()
{
    DEVICE_DESIRED_DATA* return_value;

    if ((return_value = (DEVICE_DESIRED_DATA*) malloc(sizeof(DEVICE_DESIRED_DATA))) == NULL)
    {
        LogError("malloc failed");
    }
    else
    {
        return_value->lock = Lock_Init();
        if (return_value->lock == NULL)
        {
            LogError("Lock_Init failed");
            free(return_value);
            return_value = NULL;
        }
        else
        {
            return_value->received_callback = false;
            return_value->cb_payload = NULL;
            return_value->cb_payload_size = 0;
        }
    }

    ASSERT_IS_NOT_NULL(return_value, "failed to create the device desired client data");

    return return_value;
}

static void _device_desired_data_deinit(DEVICE_DESIRED_DATA* device)
{
    if (device == NULL)
    {
        LogError("invalid parameter device");
    }
    else
    {
        free(device->cb_payload);
        Lock_Deinit(device->lock);
        free(device);
    }
}

static const char* COMPLETE_DESIRED_PAYLOAD_FORMAT =
    "{\"properties\":{\"desired\":{\"integer_property\": %d, \"string_property\": \"%s\", \"array\": [%d, \"%s\"]}}}";
static char* _malloc_and_fill_service_client_desired_payload(const char* astring, int aint)
{
    size_t length = snprintf(NULL, 0, COMPLETE_DESIRED_PAYLOAD_FORMAT, aint, astring, aint, astring);
    char* return_value = (char*) malloc(length + 1);
    if (return_value == NULL)
    {
        LogError("malloc failed");
    }
    else
    {
        (void) sprintf(return_value, COMPLETE_DESIRED_PAYLOAD_FORMAT, aint, astring, aint, astring);
    }
    return return_value;
}

static char* _malloc_and_fill_device_client_expected_desired_payload_CBOR(const char* astring, int aint)
{
    ASSERT_ARE_EQUAL(size_t, CBOR_STRING_BUFFER_SIZE, strlen(astring));
    ASSERT_IS_TRUE(-1 < aint);
    ASSERT_IS_TRUE(aint < 24);

    // {"integer_property": <0 to 23>, "string_property":"<7 characters>","array":[<0 to 23>,"<7 characters>"],"$version":<num>}
    uint8_t buffer[] = {
    /* 0: Map(3) Tag */             0xA4,
    /* 1: Text(16) Tag */           0x70,
    /* 2-17: "integer_property" */  0x69, 0x6E, 0x74, 0x65, 0x67, 0x65, 0x72, 0x5F, 0x70, 0x72, 0x6F,
                                    0x70, 0x65, 0x72, 0x74, 0x79,
    /* 18: unsigned(0 to 23) Tag w/ value TBD */      0x00,
    /* 19: Text(15) Tag */          0x6F,
    /* 20-34: "string_property" */  0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x5F, 0x70, 0x72, 0x6F, 0x70, 0x65, 0x72, 0x74, 0x79,
    /* 35: Text(7) Tag */           0x67,
    /* 36-42: 7 characters TBD */   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 43: Text(5) Tag */           0x65,
    /* 44-48: "array" */            0x61, 0x72, 0x72, 0x61, 0x79,
    /* 49: Array(2) Tag */          0x82,
    /* 50: unsigned(0 to 23) Tag w/ value TBD */      0x00,
    /* 51: Text(7) Tag */           0x67,
    /* 52-58: 7 characters TBD */   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 59: Text(8) Tag */           0x68,
    /* 60-67: "$version" */         0x24, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E,
    /* 68: unsigned(0 to 23) Tag w/ value TBD */      0x00}; // Unknown version number.

    uint8_t* return_value = (uint8_t*)malloc(sizeof(buffer));
    memcpy(return_value, buffer, sizeof(buffer));

    return_value[18] = aint;
    return_value[50] = aint;
    memcpy(return_value + 36, (uint8_t*)astring, CBOR_STRING_BUFFER_SIZE);
    memcpy(return_value + 52, (uint8_t*)astring, CBOR_STRING_BUFFER_SIZE);

    LogInfo("Filling expected_desired CBOR payload: ");
    for (size_t i = 0; i < 69; ++i)
    {
        (void)printf("%02X ", return_value[i]);
    }
    (void)printf("\n");

    return return_value;

}
static char* _malloc_and_copy_unsigned_char(const unsigned char* payload, size_t size)
{
    char* return_value;
    if (payload == NULL)
    {
        LogError("invalid parameter payload");
        return_value = NULL;
    }
    else if (size < 1)
    {
        LogError("invalid parameter size");
        return_value = NULL;
    }
    else
    {
        char* temp = (char*) malloc(size + 1);
        if (temp == NULL)
        {
            LogError("malloc failed");
            return_value = NULL;
        }
        else
        {
            return_value = (char*) memcpy(temp, payload, size);
            temp[size] = '\0';
        }
    }
    return return_value;
}

typedef struct DEVICE_REPORTED_DATA_TAG
{
    char* string_property;
    int integer_property;
    bool received_callback;   // true when device callback has been called
    int status_code;          // status reported by the callback
    LOCK_HANDLE lock;
} DEVICE_REPORTED_DATA;

static DEVICE_REPORTED_DATA* _device_reported_data_init(bool is_cbor)
{
    DEVICE_REPORTED_DATA* return_value;

    if ((return_value = (DEVICE_REPORTED_DATA*) malloc(sizeof(DEVICE_REPORTED_DATA))) == NULL)
    {
        LogError("malloc failed");
    }
    else
    {
        return_value->lock = Lock_Init();
        if (return_value->lock == NULL)
        {
            LogError("Lock_Init failed");
            free(return_value);
            return_value = NULL;
        }
        else
        {
            if (is_cbor)
            {
                return_value->string_property = (char*)_generate_unique_CBOR_string();
            }
            else
            {
                return_value->string_property = _generate_unique_string();
            }

            if (return_value->string_property == NULL)
            {
                LogError("generate unique string failed");
                Lock_Deinit(return_value->lock);
                free(return_value);
                return_value = NULL;
            }
            else
            {
                return_value->received_callback = false;
                if (is_cbor)
                {
                    return_value->integer_property = (int)_generate_new_CBOR_int();
                }
                else
                {
                    return_value->integer_property = _generate_new_int();
                }
            }
        }
    }

    ASSERT_IS_NOT_NULL(return_value, "failed to create the device reported client data");

    return return_value;
}

static void _device_reported_data_deinit(DEVICE_REPORTED_DATA* device, bool is_cbor)
{
    if (device == NULL)
    {
        LogError("invalid parameter device");
    }
    else
    {
        if (!is_cbor)
        {
            free(device->string_property);
        }
        Lock_Deinit(device->lock);
        free(device);
    }
}

static const char* REPORTED_PAYLOAD_FORMAT =
    "{\"integer_property\": %d, \"string_property\": \"%s\", \"array\": [%d, \"%s\"] }";
static char* _malloc_and_fill_reported_payload(const char* string, int num)
{
    size_t length = snprintf(NULL, 0, REPORTED_PAYLOAD_FORMAT, num, string, num, string);
    char* return_value = (char*) malloc(length + 1);
    if (return_value == NULL)
    {
        LogError("malloc failed");
    }
    else
    {
        (void) sprintf(return_value, REPORTED_PAYLOAD_FORMAT, num, string, num, string);
    }
    return return_value;
}

static uint8_t* _malloc_and_fill_reported_payload_CBOR(const char* astring, int aint, size_t* buffer_length)
{
    ASSERT_ARE_EQUAL(size_t, CBOR_STRING_BUFFER_SIZE, strlen(astring));
    ASSERT_IS_TRUE(-1 < aint);
    ASSERT_IS_TRUE(aint < 24);

    // {"integer_property": <0 to 23>, "string_property": "<7 characters>", "array": [<0 to 23>, "<7 characters>"] }
    uint8_t buffer[] = {
    /* 0: Map(3) Tag */             0xA3,
    /* 1: Text(16) Tag */           0x70,
    /* 2-17: "integer_property" */  0x69, 0x6E, 0x74, 0x65, 0x67, 0x65, 0x72, 0x5F, 0x70, 0x72, 0x6F,
                                    0x70, 0x65, 0x72, 0x74, 0x79,
    /* 18: unsigned(0 to 23) Tag w/ value TBD */      0x00,
    /* 19: Text(15) Tag */          0x6F,
    /* 20-34: "string_property" */  0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x5F, 0x70, 0x72, 0x6F, 0x70,
                                    0x65, 0x72, 0x74, 0x79,
    /* 35: Text(7) Tag */           0x67,
    /* 36-42: 7 characters TBD */   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 43: Text(5) Tag */           0x65,
    /* 44-48: "array" */            0x61, 0x72, 0x72, 0x61, 0x79,
    /* 49: Array(2) Tag */          0x82,
    /* 50: unsigned(0 to 23) Tag w/ value TBD */      0x00,
    /* 51: Text(7) Tag */           0x67,
    /* 52-58: 7 characters TBD */   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // 59 bytes total

    *buffer_length = sizeof(buffer)/sizeof(buffer[0]);

    uint8_t* return_value = (uint8_t*)malloc(sizeof(buffer));
    memcpy(return_value, buffer, sizeof(buffer));

    return_value[18] = aint;
    return_value[50] = aint;
    memcpy(return_value + 36, (uint8_t*)astring, CBOR_STRING_BUFFER_SIZE);
    memcpy(return_value + 52, (uint8_t*)astring, CBOR_STRING_BUFFER_SIZE);

    LogInfo("Filling reported CBOR payload: ");
    for (size_t i = 0; i < *buffer_length; ++i)
    {
        (void)printf("%02X ", return_value[i]);
    }
    (void)printf("\n");

    return return_value;
}

static char* _parse_json_twin_char(const char* twin_payload, const char* full_property_name)
{
    JSON_Value* root_value = json_parse_string(twin_payload);
    ASSERT_IS_NOT_NULL(root_value);
    JSON_Object* root_object = json_value_get_object(root_value);
    ASSERT_IS_NOT_NULL(root_object);

    const char* value =  json_object_dotget_string(root_object, full_property_name);
    size_t length = json_object_dotget_string_len(root_object, full_property_name);
    char* return_value = _malloc_and_copy_unsigned_char(value, length);

    json_value_free(root_value);

    return return_value;
}

static int _parse_json_twin_number(const char* twin_payload, const char* full_property_name, bool allow_for_zero)
{
    JSON_Value* root_value = json_parse_string(twin_payload);
    ASSERT_IS_NOT_NULL(root_value);
    JSON_Object* root_object = json_value_get_object(root_value);
    ASSERT_IS_NOT_NULL(root_object);

    double double_value = json_object_dotget_number(root_object, full_property_name);
    int int_value = (int)(double_value + 0.1); // Account for possible underflow by small increment and then int typecast.

    if (!allow_for_zero)
    {
        ASSERT_ARE_NOT_EQUAL(int, 0, int_value, "Failed to parse %s", full_property_name);
    }

    json_value_free(root_value);

    return int_value;
}

static char* _parse_json_twin_char_from_array(const char* twin_payload, const char* full_property_name, size_t index)
{
    JSON_Value* root_value = json_parse_string(twin_payload);
    ASSERT_IS_NOT_NULL(root_value);
    JSON_Object* root_object = json_value_get_object(root_value);
    ASSERT_IS_NOT_NULL(root_object);

    JSON_Array* array = json_object_dotget_array(root_object, full_property_name);
    ASSERT_IS_NOT_NULL(array, "Array not specified");

    const char* value =  json_array_get_string(array, index);
    size_t length = json_array_get_string_len(array, index);
    char* return_value = _malloc_and_copy_unsigned_char(value, length);

    json_value_free(root_value);

    return return_value;
}

static int _parse_json_twin_number_from_array(const char* twin_payload, const char* full_property_name, size_t index, bool allow_for_zero)
{
    JSON_Value* root_value = json_parse_string(twin_payload);
    ASSERT_IS_NOT_NULL(root_value);
    JSON_Object* root_object = json_value_get_object(root_value);
    ASSERT_IS_NOT_NULL(root_object);

    JSON_Array* array = json_object_dotget_array(root_object, full_property_name);
    ASSERT_IS_NOT_NULL(array, "Array not specified");

    double double_value = json_array_get_number(array, index);
    int int_value = (int)(double_value + 0.1); // Account for possible underflow by small increment and then int typecast.

    if (!allow_for_zero)
    {
        ASSERT_ARE_NOT_EQUAL(int, 0, int_value, "Failed to parse %s", full_property_name);
    }

    json_value_free(root_value);

    return int_value;
}

int _parse_last_cbor_byte_number(const char* twin_payload, size_t twin_payload_size)
{
    int return_value = 0;
    return return_value |= (int8_t)twin_payload[twin_payload_size - 1];
}

//
// Device Client APIs & callbacks
//
static void _set_option(const char* option_name, const void* option_data, const char* error_message)
{
    IOTHUB_CLIENT_RESULT result;

    if (iothub_moduleclient_handle)
    {
        result = IoTHubModuleClient_SetOption(iothub_moduleclient_handle, option_name, option_data);
    }
    else
    {
        result = IoTHubDeviceClient_SetOption(iothub_deviceclient_handle, option_name, option_data);
    }

    ASSERT_ARE_EQUAL(IOTHUB_CLIENT_RESULT, IOTHUB_CLIENT_OK, result, error_message);
}

static void _setup_test(IOTHUB_PROVISIONED_DEVICE* device_to_use, IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol)
{
    ASSERT_IS_NULL(iothub_deviceclient_handle, "iothub_deviceclient_handle is non-NULL on test initialization");
    ASSERT_IS_NULL(iothub_moduleclient_handle, "iothub_moduleclient_handle is non-NULL on test initialization");

    if (device_to_use->moduleConnectionString)
    {
        iothub_moduleclient_handle = IoTHubModuleClient_CreateFromConnectionString(device_to_use->moduleConnectionString, protocol);
        ASSERT_IS_NOT_NULL(iothub_moduleclient_handle, "Could not invoke IoTHubModuleClient_CreateFromconnection_string");
    }
    else
    {
        iothub_deviceclient_handle = IoTHubDeviceClient_CreateFromConnectionString(device_to_use->connectionString, protocol);
        ASSERT_IS_NOT_NULL(iothub_deviceclient_handle, "Could not invoke IoTHubDeviceClient_CreateFromconnection_string");
    }

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    _set_option(OPTION_TRUSTED_CERT, certificates, "Cannot enable trusted cert");
#endif // SET_TRUSTED_CERT_IN_SAMPLES

    if (device_to_use->howToCreate == IOTHUB_ACCOUNT_AUTH_X509)
    {
        _set_option(OPTION_X509_CERT, device_to_use->certificate, "Could not set the device x509 certificate");
        _set_option(OPTION_X509_PRIVATE_KEY, device_to_use->primaryAuthentication, "Could not set the device x509 privateKey");
    }

    bool trace = true;
    _set_option(OPTION_LOG_TRACE, &trace, "Cannot enable tracing");
}

static void _breakdown_test()
{
    LogInfo("Beginning to destroy IotHub client handle");
    if (iothub_moduleclient_handle)
    {
        IoTHubModuleClient_Destroy(iothub_moduleclient_handle);
        iothub_moduleclient_handle = NULL;
    }

    if (iothub_deviceclient_handle)
    {
        IoTHubDeviceClient_Destroy(iothub_deviceclient_handle);
        iothub_deviceclient_handle = NULL;
    }
    LogInfo("Completed destroy of IotHub client handle");
}

static void _device_twin_callback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* user_context_callback)
{
    DEVICE_DESIRED_DATA* device_desired_data = (DEVICE_DESIRED_DATA*)user_context_callback;
    if (Lock(device_desired_data->lock) == LOCK_ERROR)
    {
        LogError("Lock failed");
    }
    else
    {
        device_desired_data->update_state = update_state;
        if (device_desired_data->cb_payload != NULL)
        {
            free(device_desired_data->cb_payload);
        }
        device_desired_data->cb_payload = _malloc_and_copy_unsigned_char(payload, size);
        device_desired_data->cb_payload_size = size;
        device_desired_data->received_callback = true;
        (void) Unlock(device_desired_data->lock);
    }
}

static void _device_twin_callback_CBOR(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* user_context_callback)
{
    LogInfo("Device Twin Callback:: Received CBOR payload: len=<%lu>, data=<", (unsigned long)size);

    for (size_t i = 0; i < size; ++i)
    {
        (void)printf("%02X ", payload[i]);
    }
    (void)printf(">\n");

    _device_twin_callback(update_state, payload, size, user_context_callback);
}

static void _device_twin_callback_JSON(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* user_context_callback)
{
    LogInfo("Device Twin Callback:: Received JSON payload: len=<%lu>, data=<%.*s>\n", (unsigned long)size, (int)size, payload);
    _device_twin_callback(update_state, payload, size, user_context_callback);
}

static void _set_device_twin_callback(IOTHUB_CLIENT_DEVICE_TWIN_CALLBACK twin_callback, DEVICE_DESIRED_DATA* device)
{
    IOTHUB_CLIENT_RESULT result;

    if (iothub_moduleclient_handle)
    {
        result = IoTHubModuleClient_SetModuleTwinCallback(iothub_moduleclient_handle, twin_callback, device);
    }
    else
    {
        result = IoTHubDeviceClient_SetDeviceTwinCallback(iothub_deviceclient_handle, twin_callback, device);
    }

    ASSERT_ARE_EQUAL(IOTHUB_CLIENT_RESULT, IOTHUB_CLIENT_OK, result, "IoTHub(Device|Module)Client_SetDeviceTwinCallback failed");
}

static void _get_twin_async(IOTHUB_CLIENT_DEVICE_TWIN_CALLBACK twin_callback, DEVICE_DESIRED_DATA* device_desired_data)
{
    IOTHUB_CLIENT_RESULT result;

    if (iothub_moduleclient_handle)
    {
        result = IoTHubModuleClient_GetTwinAsync(iothub_moduleclient_handle, twin_callback, device_desired_data);
    }
    else
    {
        result = IoTHubDeviceClient_GetTwinAsync(iothub_deviceclient_handle, twin_callback, device_desired_data);
    }

    ASSERT_ARE_EQUAL(IOTHUB_CLIENT_RESULT, IOTHUB_CLIENT_OK, result, "IoTHub(Device|Module)Client_GetTwinAsync failed");
}

static void _reported_state_callback(int status_code, void* user_context_callback)
{
    LogInfo("Reported State Callback:: Received status=<%d>\n", status_code);

    DEVICE_REPORTED_DATA* device_reported_data = (DEVICE_REPORTED_DATA*) user_context_callback;
    if (Lock(device_reported_data->lock) == LOCK_ERROR)
    {
        LogError("Lock failed");
    }
    else
    {
        device_reported_data->status_code = status_code;
        device_reported_data->received_callback = true;
        (void) Unlock(device_reported_data->lock);
    }
}

static void _send_reported_state(const char* buffer, size_t bufferLen, DEVICE_REPORTED_DATA* device_reported_data)
{
    IOTHUB_CLIENT_RESULT result;

    if (iothub_moduleclient_handle != NULL)
    {
        result = IoTHubModuleClient_SendReportedState(iothub_moduleclient_handle, (unsigned char*) buffer, bufferLen, _reported_state_callback, device_reported_data);
    }
    else
    {
        result = IoTHubDeviceClient_SendReportedState(iothub_deviceclient_handle, (unsigned char*) buffer, bufferLen, _reported_state_callback, device_reported_data);
    }

    ASSERT_ARE_EQUAL(IOTHUB_CLIENT_RESULT, IOTHUB_CLIENT_OK, result, "IoTHub(Device|Module)Client_SendReportedState failed");
}

static void _send_event_async(IOTHUB_MESSAGE_HANDLE msgHandle)
{
    IOTHUB_CLIENT_RESULT result;

    if (iothub_moduleclient_handle != NULL)
    {
        result = IoTHubModuleClient_SendEventAsync(iothub_moduleclient_handle, msgHandle, NULL, NULL);
    }
    else
    {
        result = IoTHubDeviceClient_SendEventAsync(iothub_deviceclient_handle, msgHandle, NULL, NULL);
    }

    ASSERT_ARE_EQUAL(IOTHUB_CLIENT_RESULT, IOTHUB_CLIENT_OK, result, "IoTHub(Device|Module)Client_SendEventAsync failed");
}

//
// Service Client APIs
//
static void _service_client_update_twin(IOTHUB_SERVICE_CLIENT_DEVICE_TWIN_HANDLE serviceclient_devicetwin_handle, IOTHUB_PROVISIONED_DEVICE* device_to_use, const char* twin_json)
{
    char* twin_response;

    LogInfo("Beginning update of twin via Service SDK");

    if (device_to_use->moduleId != NULL)
    {
        twin_response = IoTHubDeviceTwin_UpdateModuleTwin(serviceclient_devicetwin_handle, device_to_use->deviceId, device_to_use->moduleId, twin_json);
    }
    else
    {
        twin_response = IoTHubDeviceTwin_UpdateTwin(serviceclient_devicetwin_handle, device_to_use->deviceId, twin_json);
    }

    ASSERT_IS_NOT_NULL(twin_response, "IoTHubDeviceTwin_Update(Module)Twin failed");

    LogInfo("Twin response from Service SDK after update is <%s>\n", twin_response);
    free(twin_response);
}

static char* _service_client_get_twin(IOTHUB_SERVICE_CLIENT_DEVICE_TWIN_HANDLE serviceclient_devicetwin_handle, IOTHUB_PROVISIONED_DEVICE* device_to_use)
{
    char* twin_data;

    if (device_to_use->moduleId != NULL)
    {
        twin_data = IoTHubDeviceTwin_GetModuleTwin(serviceclient_devicetwin_handle, device_to_use->deviceId, device_to_use->moduleId);
    }
    else
    {
        twin_data = IoTHubDeviceTwin_GetTwin(serviceclient_devicetwin_handle, device_to_use->deviceId);
    }

    ASSERT_IS_NOT_NULL(twin_data, "IoTHubDeviceTwin_Get(Module)Twin failed");

    LogInfo("Twin data retrieved from Service SDK is <%s>\n", twin_data);
    return twin_data;
}

//
// dt_e2e Tests
//
void dt_e2e_init(bool testing_modules)
{
    int result = IoTHub_Init();
    ASSERT_ARE_EQUAL(int, 0, result, "IoTHub_Init failed");

    /* the return value from the second init is deliberatly ignored. */
    (void)IoTHub_Init();

    iothub_accountinfo_handle = IoTHubAccount_Init(testing_modules);
    ASSERT_IS_NOT_NULL(iothub_accountinfo_handle);
}

void dt_e2e_deinit(void)
{
    IoTHubAccount_deinit(iothub_accountinfo_handle);

    // Need a double deinit
    IoTHub_Deinit();
    IoTHub_Deinit();
}

void dt_e2e_send_reported_test(IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol, IOTHUB_ACCOUNT_AUTH_METHOD account_auth_method)
{
    IOTHUB_PROVISIONED_DEVICE* device_to_use = IoTHubAccount_GetDevice(iothub_accountinfo_handle, account_auth_method);
    _setup_test(device_to_use, protocol);

    bool is_cbor = true;
    DEVICE_REPORTED_DATA* device_reported_data = _device_reported_data_init(!is_cbor);

    // Generate and send the reported payload to IoT Hub.
    char* buffer = _malloc_and_fill_reported_payload(device_reported_data->string_property, device_reported_data->integer_property);
    ASSERT_IS_NOT_NULL(buffer, "failed to allocate and prepare the payload for SendReportedState");
    _send_reported_state(buffer, strlen(buffer), device_reported_data);

    // Receive IoT Hub response.
    int status_code = 400;
    time_t begin_operation;
    time_t now_time;

    begin_operation = time(NULL);

    while (now_time = time(NULL), difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME)
    {
        if (Lock(device_reported_data->lock) != LOCK_OK)
        {
            ASSERT_FAIL("Lock failed");
        }
        else
        {
            if (device_reported_data->received_callback)
            {
                status_code = device_reported_data->status_code;
                Unlock(device_reported_data->lock);
                break;
            }
            Unlock(device_reported_data->lock);
        }
        ThreadAPI_Sleep(1000);
    }

    // Check results.
    if (Lock(device_reported_data->lock) != LOCK_OK)
    {
        ASSERT_FAIL("Lock failed");
    }
    else
    {
        ASSERT_IS_TRUE(status_code < 300, "SendReported status_code is an error");

        // Connect service client to IoT Hub.
        const char* connection_string = IoTHubAccount_GetIoTHubConnString(iothub_accountinfo_handle);
        IOTHUB_SERVICE_CLIENT_AUTH_HANDLE iothub_serviceclient_handle = IoTHubServiceClientAuth_CreateFromConnectionString(connection_string);
        ASSERT_IS_NOT_NULL(iothub_serviceclient_handle, "IoTHubServiceClientAuth_CreateFromConnectionString failed");

        IOTHUB_SERVICE_CLIENT_DEVICE_TWIN_HANDLE serviceclient_devicetwin_handle = IoTHubDeviceTwin_Create(iothub_serviceclient_handle);
        ASSERT_IS_NOT_NULL(serviceclient_devicetwin_handle, "IoTHubDeviceTwin_Create failed");

        // Retrieve service client twin and compare with reported data sent.
        char* twin_data = _service_client_get_twin(serviceclient_devicetwin_handle, device_to_use);

        char* string_property = _parse_json_twin_char(twin_data, "properties.reported.string_property");
        ASSERT_ARE_EQUAL(char_ptr, device_reported_data->string_property, string_property, "string data retrieved differs from reported");

        bool allow_for_zero = true;
        int integer_property = _parse_json_twin_number(twin_data, "properties.reported.integer_property", allow_for_zero);
        ASSERT_ARE_EQUAL(int, device_reported_data->integer_property, integer_property, "integer data retrieved differs from reported");

        (void) Unlock(device_reported_data->lock);

        // Cleanup
        free(string_property);
        free(twin_data);
        IoTHubDeviceTwin_Destroy(serviceclient_devicetwin_handle);
        IoTHubServiceClientAuth_Destroy(iothub_serviceclient_handle);
    }

    // Cleanup
    free(buffer);
    _device_reported_data_deinit(device_reported_data, !is_cbor);
    _breakdown_test();
}

void dt_e2e_get_complete_desired_test(IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol, IOTHUB_ACCOUNT_AUTH_METHOD account_auth_method)
{
    IOTHUB_PROVISIONED_DEVICE* device_to_use = IoTHubAccount_GetDevice(iothub_accountinfo_handle, account_auth_method);
    _setup_test(device_to_use, protocol);

    // Connect device to IoT Hub. Subscribe to twin topic.
    DEVICE_DESIRED_DATA* device_desired_data = _device_desired_data_init();
    _set_device_twin_callback(_device_twin_callback, device_desired_data);

    // Twin registrations to the cloud happen asyncronously because we're using the convenience layer.  There is an (unavoidable)
    // race potential in tests like this where we create handles and immediately invoke the service SDK.  Namely without this
    // sleep, we could:
    // 1 - Register for the full twin (which happens via IoTHubDeviceClient_SetDeviceTwinCallback)
    // 2 - Have the service SDK update the twin (see _service_client_update_twin), but it takes a while
    // 3 - The client receives its full twin, which will just be empty data given (2) isn't completed
    // 4 - When the client receives full twin, it will register for PATCH changes
    // 5 - The server only now completes (2), setting the full twin.  However this has happened *after* it received
    //     the subscribe for PATCH and therefore it doesn't send down the PATCH of the full twin.
    // Apps in field will rarely hit this, as it requries service SDK & client handle to be invoked almost simultaneously.
    // And the client *is* registered for future twin updates on this handle, so it would get future changes.
    LogInfo("Sleeping for a few seconds as client-side registers with twin");
    ThreadAPI_Sleep(5000);

    // Connect service client to IoT Hub.
    const char* connection_string = IoTHubAccount_GetIoTHubConnString(iothub_accountinfo_handle);
    IOTHUB_SERVICE_CLIENT_AUTH_HANDLE iothub_serviceclient_handle = IoTHubServiceClientAuth_CreateFromConnectionString(connection_string);
    ASSERT_IS_NOT_NULL(iothub_serviceclient_handle, "IoTHubServiceClientAuth_CreateFromConnectionString failed");

    IOTHUB_SERVICE_CLIENT_DEVICE_TWIN_HANDLE serviceclient_devicetwin_handle = IoTHubDeviceTwin_Create(iothub_serviceclient_handle);
    ASSERT_IS_NOT_NULL(serviceclient_devicetwin_handle, "IoTHubDeviceTwin_Create failed");

    // Get twin initial desired version via service client.
    // Format:: {"properties": {"desired":{"$version":[value]},"reported":{"$version":[value]}}}
    char* twin_data = _service_client_get_twin(serviceclient_devicetwin_handle, device_to_use);
    bool allow_for_zero = true;
    int64_t initial_version = (int64_t)_parse_json_twin_number(twin_data, "properties.desired.$version", !allow_for_zero);

    // Update service client twin to prompt a desired property PATCH message to device.
    char* expected_desired_string = _generate_unique_string();
    int expected_desired_integer = _generate_new_int();
    char* buffer = _malloc_and_fill_service_client_desired_payload(expected_desired_string, expected_desired_integer);
    ASSERT_IS_NOT_NULL(buffer, "failed to create the payload for IoTHubDeviceTwin_UpdateTwin");
    _service_client_update_twin(serviceclient_devicetwin_handle, device_to_use, buffer);

    // Receive IoT Hub response.
    int integer_property = 0;
    char* string_property = NULL;
    int integer_property_from_array = 0;
    char* string_property_from_array = NULL;

    time_t begin_operation;
    time_t now_time;

    begin_operation = time(NULL);

    while (now_time = time(NULL), difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME)
    {
        if (Lock(device_desired_data->lock) != LOCK_OK)
        {
            ASSERT_FAIL("Lock failed");
        }
        else
        {
            if ((device_desired_data->received_callback) && (device_desired_data->cb_payload != NULL))
            {
                int64_t current_version;
                if (device_desired_data->update_state == DEVICE_TWIN_UPDATE_PARTIAL)
                {
                    bool allow_for_zero = true;
                    current_version = (int64_t)_parse_json_twin_number(device_desired_data->cb_payload, "$version", !allow_for_zero);
                }
                else if (device_desired_data->update_state == DEVICE_TWIN_UPDATE_COMPLETE)
                {
                    Unlock(device_desired_data->lock);
                    ThreadAPI_Sleep(1000);
                    continue;
                }

                if (current_version == initial_version)
                {
                    // There is a potential race where we'll get the callback for deviceTwin availability on the initial twin, not on the
                    // updated one.  We determine this by looking at $version and if they're the same, it means we haven't got update yet.
                    LogInfo("The version of twin on callback is identical to initially set (%ld). Waiting for update\n", current_version);
                    Unlock(device_desired_data->lock);
                    ThreadAPI_Sleep(1000);
                    continue;
                }

                // Retrieve results.
                // Format:: {"$version":[value]}
                bool allow_for_zero = true;
                switch (device_desired_data->update_state)
                {
                case DEVICE_TWIN_UPDATE_PARTIAL:
                    integer_property = _parse_json_twin_number(device_desired_data->cb_payload, "integer_property", allow_for_zero);
                    string_property = _parse_json_twin_char(device_desired_data->cb_payload, "string_property");
                    integer_property_from_array = _parse_json_twin_number_from_array(device_desired_data->cb_payload, "array", 0, allow_for_zero);
                    string_property_from_array = _parse_json_twin_char_from_array(device_desired_data->cb_payload, "array", 1);
                    break;
                default: // invalid update state
                    ASSERT_FAIL("Invalid update_state reported");
                    break;
                }
                if ((string_property != NULL) && (integer_property != 0))
                {
                    Unlock(device_desired_data->lock);
                    break;
                }
            }
            Unlock(device_desired_data->lock);
        }
        ThreadAPI_Sleep(1000);
    }

    ASSERT_IS_TRUE(difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME, "Timeout waiting for twin message");

    // Unsubscribe
    _set_device_twin_callback(NULL, NULL);

    // Check results.
    if (Lock(device_desired_data->lock) != LOCK_OK)
    {
        ASSERT_FAIL("Lock failed");
    }
    else
    {
        ASSERT_ARE_EQUAL(char_ptr, expected_desired_string, string_property, "string data retrieved differs from expected");
        ASSERT_ARE_EQUAL(int, expected_desired_integer, integer_property, "integer data retrieved differs from expected");
        ASSERT_ARE_EQUAL(char_ptr, expected_desired_string, string_property_from_array, "string data (from array) retrieved differs from expected");
        ASSERT_ARE_EQUAL(int, expected_desired_integer, integer_property_from_array, "integer data (from array) retrieved differs from expected");

        (void)Unlock(device_desired_data->lock);
    }

    // Cleanup
    free(string_property_from_array);
    free(string_property);
    free(buffer);
    free(expected_desired_string);
    free(twin_data);
    IoTHubDeviceTwin_Destroy(serviceclient_devicetwin_handle);
    IoTHubServiceClientAuth_Destroy(iothub_serviceclient_handle);
    _device_desired_data_deinit(device_desired_data);
    _breakdown_test();
}

void _client_create_with_properties_and_send_d2c(IOTHUB_PROVISIONED_DEVICE* device_to_use, MAP_HANDLE mapHandle)
{
    IOTHUB_MESSAGE_HANDLE msgHandle;

    char messageStr[512];
    int len = snprintf(messageStr, sizeof(messageStr), "Happy little message from device '%s'", device_to_use->deviceId);
    if (len < 0 || len == sizeof(messageStr))
    {
        ASSERT_FAIL("messageStr is not large enough!");
        return;
    }

    msgHandle = IoTHubMessage_CreateFromByteArray((const unsigned char*)messageStr, len);
    ASSERT_IS_NOT_NULL(msgHandle, "Could not create the D2C message to be sent");

    MAP_HANDLE msgMapHandle = IoTHubMessage_Properties(msgHandle);

    const char*const* keys;
    const char*const* values;
    size_t propCount;

    MAP_RESULT mapResult = Map_GetInternals(mapHandle, &keys, &values, &propCount);
    if (mapResult == MAP_OK)
    {
        for (size_t i = 0; i < propCount; i++)
        {
            if (Map_AddOrUpdate(msgMapHandle, keys[i], values[i]) != MAP_OK)
            {
                ASSERT_FAIL("Map_AddOrUpdate failed!");
            }
        }
    }

    _send_event_async(msgHandle);
    IoTHubMessage_Destroy(msgHandle);
}

void dt_e2e_send_reported_test_svc_fault_ctrl_kill_Tcp(IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol, IOTHUB_ACCOUNT_AUTH_METHOD account_auth_method)
{
    IOTHUB_PROVISIONED_DEVICE* device_to_use = IoTHubAccount_GetDevice(iothub_accountinfo_handle, account_auth_method);
    _setup_test(device_to_use, protocol);

    bool is_cbor = true;
    DEVICE_REPORTED_DATA* device_reported_data = _device_reported_data_init(!is_cbor);

    // Generate and send the reported payload to IoT Hub.
    char* buffer = _malloc_and_fill_reported_payload(device_reported_data->string_property, device_reported_data->integer_property);
    ASSERT_IS_NOT_NULL(buffer, "failed to allocate and prepare the payload for SendReportedState");
    _send_reported_state(buffer, strlen(buffer), device_reported_data);

    ThreadAPI_Sleep(3000);

    // Receive IoT Hub response.
    int status_code = 400;
    time_t begin_operation;
    time_t now_time;

    begin_operation = time(NULL);

    while (now_time = time(NULL), difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME)
    {
        if (Lock(device_reported_data->lock) != LOCK_OK)
        {
            ASSERT_FAIL("Lock failed");
        }
        else
        {
            if (device_reported_data->received_callback)
            {
                status_code = device_reported_data->status_code;
                Unlock(device_reported_data->lock);
                break;
            }
            Unlock(device_reported_data->lock);
        }
        ThreadAPI_Sleep(1000);
    }
    ASSERT_IS_TRUE(status_code < 300, "SendReported status_code is an error");

    // Send the Event from the client
    MAP_HANDLE propMap = Map_Create(NULL);
    if (Map_AddOrUpdate(propMap, "AzIoTHub_FaultOperationType", "KillTcp") != MAP_OK)
    {
        ASSERT_FAIL("Map_AddOrUpdate failed for AzIoTHub_FaultOperationType!");
    }

    if (Map_AddOrUpdate(propMap, "AzIoTHub_FaultOperationCloseReason", "boom") != MAP_OK)
    {
        ASSERT_FAIL("Map_AddOrUpdate failed for AzIoTHub_FaultOperationCloseReason!");
    }

    if (Map_AddOrUpdate(propMap, "AzIoTHub_FaultOperationDelayInSecs", "1") != MAP_OK)
    {
        ASSERT_FAIL("Map_AddOrUpdate failed for AzIoTHub_FaultOperationDelayInSecs!");
    }
    (void)printf("Send fault control message...\r\n");
    _client_create_with_properties_and_send_d2c(device_to_use, propMap);
    Map_Destroy(propMap);

    ThreadAPI_Sleep(3000);

    // Send reported payload to IoT Hub again.
    _send_reported_state(buffer, strlen(buffer), device_reported_data);

    ThreadAPI_Sleep(3000);

    // Receive IoT Hub response. Check result.
    status_code = 400;
    begin_operation = time(NULL);

    while (now_time = time(NULL), difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME)
    {
        if (Lock(device_reported_data->lock) != LOCK_OK)
        {
            ASSERT_FAIL("Lock failed");
        }
        else
        {
            if (device_reported_data->received_callback)
            {
                status_code = device_reported_data->status_code;
                Unlock(device_reported_data->lock);
                break;
            }
            Unlock(device_reported_data->lock);
        }
        ThreadAPI_Sleep(1000);
    }
    ASSERT_IS_TRUE(status_code < 300, "SendReported status_code is an error");

    // Cleanup
    free(buffer);
    _device_reported_data_deinit(device_reported_data, !is_cbor);
    _breakdown_test();
}

void dt_e2e_get_complete_desired_test_svc_fault_ctrl_kill_Tcp(IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol, IOTHUB_ACCOUNT_AUTH_METHOD account_auth_method)
{
    IOTHUB_PROVISIONED_DEVICE* device_to_use = IoTHubAccount_GetDevice(iothub_accountinfo_handle, account_auth_method);
    _setup_test(device_to_use, protocol);

    // Connect device to IoT Hub. Subscribe to twin topic.
    DEVICE_DESIRED_DATA* device_desired_data = _device_desired_data_init();
    _set_device_twin_callback(_device_twin_callback, device_desired_data);

    // Connect service client to IoT Hub.
    const char* connection_string = IoTHubAccount_GetIoTHubConnString(iothub_accountinfo_handle);
    IOTHUB_SERVICE_CLIENT_AUTH_HANDLE iothub_serviceclient_handle = IoTHubServiceClientAuth_CreateFromConnectionString(connection_string);
    ASSERT_IS_NOT_NULL(iothub_serviceclient_handle, "IoTHubServiceClientAuth_CreateFromConnectionString failed");

    IOTHUB_SERVICE_CLIENT_DEVICE_TWIN_HANDLE serviceclient_devicetwin_handle = IoTHubDeviceTwin_Create(iothub_serviceclient_handle);
    ASSERT_IS_NOT_NULL(serviceclient_devicetwin_handle, "IoTHubDeviceTwin_Create failed");

    // Update service client twin to prompt a desired property PATCH message to device.
    char* expected_desired_string = _generate_unique_string();
    int expected_desired_integer = _generate_new_int();
    char* buffer = _malloc_and_fill_service_client_desired_payload(expected_desired_string, expected_desired_integer);
    ASSERT_IS_NOT_NULL(buffer, "failed to create the payload for IoTHubDeviceTwin_UpdateTwin");
    _service_client_update_twin(serviceclient_devicetwin_handle, device_to_use, buffer);

    ThreadAPI_Sleep(3000);

    // Receive IoT Hub response.
    int status_code = 400;
    time_t begin_operation;
    time_t now_time;

    begin_operation = time(NULL);

    while (now_time = time(NULL), difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME)
    {
        if (Lock(device_desired_data->lock) != LOCK_OK)
        {
            ASSERT_FAIL("Lock failed");
        }
        else
        {
            if (device_desired_data->received_callback)
            {
                status_code = 0;
                Unlock(device_desired_data->lock);
                break;
            }
            Unlock(device_desired_data->lock);
        }
        ThreadAPI_Sleep(1000);
    }
    ASSERT_IS_TRUE(status_code == 0, "SendReported status_code is an error");

    // Send the Event from the device client
    MAP_HANDLE propMap = Map_Create(NULL);
    if (Map_AddOrUpdate(propMap, "AzIoTHub_FaultOperationType", "KillTcp") != MAP_OK)
    {
        ASSERT_FAIL("Map_AddOrUpdate failed for AzIoTHub_FaultOperationType!");
    }

    if (Map_AddOrUpdate(propMap, "AzIoTHub_FaultOperationCloseReason", "boom") != MAP_OK)
    {
        ASSERT_FAIL("Map_AddOrUpdate failed for AzIoTHub_FaultOperationCloseReason!");
    }

    if (Map_AddOrUpdate(propMap, "AzIoTHub_FaultOperationDelayInSecs", "1") != MAP_OK)
    {
        ASSERT_FAIL("Map_AddOrUpdate failed for AzIoTHub_FaultOperationDelayInSecs!");
    }
    (void)printf("Send fault control message...\r\n");
    _client_create_with_properties_and_send_d2c(device_to_use, propMap);
    Map_Destroy(propMap);

    ThreadAPI_Sleep(3000);

    // Update service client twin again.
    _service_client_update_twin(serviceclient_devicetwin_handle, device_to_use, buffer);

    ThreadAPI_Sleep(3000);

    // Receive IoT Hub response. Check result.
    status_code = 400;
    begin_operation = time(NULL);

    while (now_time = time(NULL), difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME)
    {
        if (Lock(device_desired_data->lock) != LOCK_OK)
        {
            ASSERT_FAIL("Lock failed");
        }
        else
        {
            if (device_desired_data->received_callback)
            {
                status_code = 0;
                Unlock(device_desired_data->lock);
                break;
            }
            Unlock(device_desired_data->lock);
        }
        ThreadAPI_Sleep(1000);
    }
    ASSERT_IS_TRUE(status_code == 0, "SendReported status_code is an error");

    // Unsubscribe
    _set_device_twin_callback(NULL, NULL);

    // Cleanup
    free(expected_desired_string);
    free(buffer);
    IoTHubDeviceTwin_Destroy(serviceclient_devicetwin_handle);
    IoTHubServiceClientAuth_Destroy(iothub_serviceclient_handle);
    _device_desired_data_deinit(device_desired_data);
    _breakdown_test();
}

static void _request_twin_and_wait_for_response(IOTHUB_PROVISIONED_DEVICE* device_to_use, DEVICE_TWIN_UPDATE_STATE update_state, bool is_cbor)
{
    bool callback_received;
    time_t begin_operation;
    time_t now_time;

    DEVICE_DESIRED_DATA* device_desired_data = _device_desired_data_init();

    if (update_state == DEVICE_TWIN_UPDATE_COMPLETE)
    {
        if (is_cbor)
        {
            _get_twin_async(_device_twin_callback_CBOR, device_desired_data);
        }
        else
        {
            _get_twin_async(_device_twin_callback_JSON, device_desired_data);
        }

        callback_received = false;
        begin_operation = time(NULL);

        // Receive IoT Hub response.
        while (now_time = time(NULL), difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME)
        {
            if (Lock(device_desired_data->lock) != LOCK_OK)
            {
                ASSERT_FAIL("Lock failed");
            }
            else
            {
                // Check results.
                if (device_desired_data->received_callback)
                {
                    ASSERT_ARE_EQUAL(DEVICE_TWIN_UPDATE_STATE, device_desired_data->update_state, DEVICE_TWIN_UPDATE_COMPLETE);
                    ASSERT_IS_NOT_NULL(device_desired_data->cb_payload);
                    ASSERT_IS_TRUE(device_desired_data->cb_payload_size > 0);
                    callback_received = device_desired_data->received_callback;
                    Unlock(device_desired_data->lock);
                    break;
                }
                Unlock(device_desired_data->lock);
            }
            ThreadAPI_Sleep(1000);
        }
        ASSERT_IS_TRUE(callback_received, "Did not receive the GetTwinAsync callback");
    }

    // Cleanup
    _device_desired_data_deinit(device_desired_data);
}

void dt_e2e_get_twin_async_test(IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol, IOTHUB_ACCOUNT_AUTH_METHOD account_auth_method)
{
    IOTHUB_PROVISIONED_DEVICE* device_to_use = IoTHubAccount_GetDevice(iothub_accountinfo_handle, account_auth_method);
    _setup_test(device_to_use, protocol);

    bool is_cbor = true;
    _request_twin_and_wait_for_response(device_to_use, DEVICE_TWIN_UPDATE_COMPLETE, !is_cbor);

    // CLeanup
    _breakdown_test();
}

// dt_e2e_send_module_id_test makes sure that when OPTION_MODEL_ID is specified at creation time,
// that the Service Twin has it specified.
void dt_e2e_send_module_id_test(IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol, IOTHUB_ACCOUNT_AUTH_METHOD account_auth_method, const char* model_id)
{
    IOTHUB_PROVISIONED_DEVICE* device_to_use = IoTHubAccount_GetDevice(iothub_accountinfo_handle, account_auth_method);
    _setup_test(device_to_use, protocol);
    _set_option(OPTION_MODEL_ID, model_id, "Cannot specify model_id"); // Set prior to network I/O.

    // Connect device to IoT Hub.
    // We do not use the returned device twin, which doesn't contain the device's model_id.
    bool is_cbor = true;
    _request_twin_and_wait_for_response(device_to_use, DEVICE_TWIN_UPDATE_COMPLETE, !is_cbor);

    // Connect service client to IoT Hub.
    const char* connection_string = IoTHubAccount_GetIoTHubConnString(iothub_accountinfo_handle);
    IOTHUB_SERVICE_CLIENT_AUTH_HANDLE iothub_serviceclient_handle = IoTHubServiceClientAuth_CreateFromConnectionString(connection_string);
    ASSERT_IS_NOT_NULL(iothub_serviceclient_handle, "IoTHubServiceClientAuth_CreateFromConnectionString failed");

    IOTHUB_SERVICE_CLIENT_DEVICE_TWIN_HANDLE serviceclient_devicetwin_handle = IoTHubDeviceTwin_Create(iothub_serviceclient_handle);
    ASSERT_IS_NOT_NULL(serviceclient_devicetwin_handle, "IoTHubDeviceTwin_Create failed");

    // Get Twin data and compare model_id.
    char* twin_data = _service_client_get_twin(serviceclient_devicetwin_handle, device_to_use);
    char* parsed_model_id = _parse_json_twin_char(twin_data, "modelId");
    ASSERT_ARE_EQUAL(char_ptr, model_id, parsed_model_id);

    // Cleanup
    free(parsed_model_id);
    free(twin_data);
    IoTHubDeviceTwin_Destroy(serviceclient_devicetwin_handle);
    IoTHubServiceClientAuth_Destroy(iothub_serviceclient_handle);
    _breakdown_test();
}

void dt_e2e_send_reported_CBOR_test(IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol, IOTHUB_ACCOUNT_AUTH_METHOD account_auth_method)
{
    IOTHUB_PROVISIONED_DEVICE* device_to_use = IoTHubAccount_GetDevice(iothub_accountinfo_handle, account_auth_method);
    _setup_test(device_to_use, protocol);

    OPTION_TWIN_CONTENT_TYPE_VALUE ct = OPTION_TWIN_CONTENT_TYPE_CBOR;
    _set_option(OPTION_TWIN_CONTENT_TYPE, &ct, "Cannot enable CBOR"); // Set prior to network I/O.

    bool is_cbor = true;
    DEVICE_REPORTED_DATA* device_reported_data = _device_reported_data_init(is_cbor);

    // Generate and send the reported payload to IoT Hub.
    size_t buffer_length;
    uint8_t* buffer = _malloc_and_fill_reported_payload_CBOR(device_reported_data->string_property, device_reported_data->integer_property, &buffer_length);
    ASSERT_IS_NOT_NULL(buffer, "failed to allocate and prepare the payload for SendReportedState");
    _send_reported_state((char*)buffer, buffer_length, device_reported_data);

    // Receive IoT Hub response.
    int status_code = 400;
    time_t begin_operation;
    time_t now_time;

    begin_operation = time(NULL);

    while (now_time = time(NULL), difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME)
    {
        if (Lock(device_reported_data->lock) != LOCK_OK)
        {
            ASSERT_FAIL("Lock failed");
        }
        else
        {
            if (device_reported_data->received_callback)
            {
                status_code = device_reported_data->status_code;
                Unlock(device_reported_data->lock);
                break;
            }
            Unlock(device_reported_data->lock);
        }
        ThreadAPI_Sleep(1000);
    }

    // Check results.
    if (Lock(device_reported_data->lock) != LOCK_OK)
    {
        ASSERT_FAIL("Lock failed");
    }
    else
    {
        ASSERT_IS_TRUE(status_code < 300, "SendReported status_code is an error");

        // Connect service client to IoT Hub.
        const char* connection_string = IoTHubAccount_GetIoTHubConnString(iothub_accountinfo_handle);
        IOTHUB_SERVICE_CLIENT_AUTH_HANDLE iothub_serviceclient_handle = IoTHubServiceClientAuth_CreateFromConnectionString(connection_string);
        ASSERT_IS_NOT_NULL(iothub_serviceclient_handle, "IoTHubServiceClientAuth_CreateFromConnectionString failed");

        IOTHUB_SERVICE_CLIENT_DEVICE_TWIN_HANDLE serviceclient_devicetwin_handle = IoTHubDeviceTwin_Create(iothub_serviceclient_handle);
        ASSERT_IS_NOT_NULL(serviceclient_devicetwin_handle, "IoTHubDeviceTwin_Create failed");

        // Retrieve service client twin and compare with reported data sent.
        char* twin_data = _service_client_get_twin(serviceclient_devicetwin_handle, device_to_use);

        char* string_property = _parse_json_twin_char(twin_data, "properties.reported.string_property");
        ASSERT_ARE_EQUAL(char_ptr, device_reported_data->string_property, string_property, "string data retrieved differs from reported");

        bool allow_for_zero = true;
        int integer_property = _parse_json_twin_number(twin_data, "properties.reported.integer_property", allow_for_zero);
        ASSERT_ARE_EQUAL(int, device_reported_data->integer_property, integer_property, "integer data retrieved differs from reported");

        (void) Unlock(device_reported_data->lock);

        // Cleanup
        free(string_property);
        free(twin_data);
        IoTHubDeviceTwin_Destroy(serviceclient_devicetwin_handle);
        IoTHubServiceClientAuth_Destroy(iothub_serviceclient_handle);
    }

    // Cleanup
    free(buffer);
    _device_reported_data_deinit(device_reported_data, is_cbor);
    _breakdown_test();
}

void dt_e2e_get_complete_desired_CBOR_test(IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol, IOTHUB_ACCOUNT_AUTH_METHOD account_auth_method)
{
    IOTHUB_PROVISIONED_DEVICE* device_to_use = IoTHubAccount_GetDevice(iothub_accountinfo_handle, account_auth_method);
    _setup_test(device_to_use, protocol);

    OPTION_TWIN_CONTENT_TYPE_VALUE ct = OPTION_TWIN_CONTENT_TYPE_CBOR;
    _set_option(OPTION_TWIN_CONTENT_TYPE, &ct, "Cannot enable CBOR"); // Set prior to network I/O.

    // Connect device to IoT Hub. Subscribe to twin topic.
    DEVICE_DESIRED_DATA* device_desired_data = _device_desired_data_init();
    _set_device_twin_callback(_device_twin_callback_CBOR, device_desired_data);

    // Twin registrations to the cloud happen asyncronously because we're using the convenience layer.  There is an (unavoidable)
    // race potential in tests like this where we create handles and immediately invoke the service SDK.  Namely without this
    // sleep, we could:
    // 1 - Register for the full twin (which happens via IoTHubDeviceClient_SetDeviceTwinCallback)
    // 2 - Have the service SDK update the twin (see _service_client_update_twin), but it takes a while
    // 3 - The client receives its full twin, which will just be empty data given (2) isn't completed
    // 4 - When the client receives full twin, it will register for PATCH changes
    // 5 - The server only now completes (2), setting the full twin.  However this has happened *after* it received
    //     the subscribe for PATCH and therefore it doesn't send down the PATCH of the full twin.
    // Apps in field will rarely hit this, as it requries service SDK & client handle to be invoked almost simultaneously.
    // And the client *is* registered for future twin updates on this handle, so it would get future changes.
    LogInfo("Sleeping for a few seconds as client-side registers with twin");
    ThreadAPI_Sleep(5000);

    // Connect service client to IoT Hub.
    const char* connection_string = IoTHubAccount_GetIoTHubConnString(iothub_accountinfo_handle);
    IOTHUB_SERVICE_CLIENT_AUTH_HANDLE iothub_serviceclient_handle = IoTHubServiceClientAuth_CreateFromConnectionString(connection_string);
    ASSERT_IS_NOT_NULL(iothub_serviceclient_handle, "IoTHubServiceClientAuth_CreateFromConnectionString failed");

    IOTHUB_SERVICE_CLIENT_DEVICE_TWIN_HANDLE serviceclient_devicetwin_handle = IoTHubDeviceTwin_Create(iothub_serviceclient_handle);
    ASSERT_IS_NOT_NULL(serviceclient_devicetwin_handle, "IoTHubDeviceTwin_Create failed");

    // Get twin initial desired version via service client.
    // Format:: {"properties": {"desired":{"$version":[value]},"reported":{"$version":[value]}}}
    char* twin_data = _service_client_get_twin(serviceclient_devicetwin_handle, device_to_use);
    bool allow_for_zero = true;
    int64_t initial_version = (int64_t)_parse_json_twin_number(twin_data, "properties.desired.$version", !allow_for_zero);

    // Update service client twin to prompt a desired property PATCH message to device.
    char* expected_desired_string = _generate_unique_CBOR_string();
    int expected_desired_integer = _generate_new_CBOR_int();
    char* buffer = _malloc_and_fill_service_client_desired_payload(expected_desired_string, expected_desired_integer);
    ASSERT_IS_NOT_NULL(buffer, "failed to create the payload for IoTHubDeviceTwin_UpdateTwin");
    _service_client_update_twin(serviceclient_devicetwin_handle, device_to_use, buffer);

    // Create expected payload from service client, translated by IoT Hub into CBOR:
    char* expected_buffer = _malloc_and_fill_device_client_expected_desired_payload_CBOR(expected_desired_string, expected_desired_integer);

    // Receive IoT Hub response.
    time_t begin_operation;
    time_t now_time;

    begin_operation = time(NULL);

    while (now_time = time(NULL), difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME)
    {
        LOCK_RESULT lock_result;
        if ((lock_result = Lock(device_desired_data->lock)) != LOCK_OK)
        {
            ASSERT_FAIL("Lock failed");
        }
        else
        {
            if ((device_desired_data->received_callback) && (device_desired_data->cb_payload != NULL))
            {
                int64_t current_version = 0;
                if (device_desired_data->update_state == DEVICE_TWIN_UPDATE_PARTIAL)
                {
                    current_version = (int64_t)_parse_last_cbor_byte_number(device_desired_data->cb_payload, device_desired_data->cb_payload_size);
                }
                else if (device_desired_data->update_state == DEVICE_TWIN_UPDATE_COMPLETE)
                {
                    Unlock(device_desired_data->lock);
                    ThreadAPI_Sleep(1000);
                    continue;
                }

                if (current_version == initial_version)
                {
                    // There is a potential race where we'll get the callback for deviceTwin availability on the initial twin, not on the
                    // updated one.  We determine this by looking at $version and if they're the same, it means we haven't got update yet.
                    LogInfo("The version of twin on callback is identical to initially set (%ld). Waiting for update\n", current_version);
                    Unlock(device_desired_data->lock);
                    ThreadAPI_Sleep(1000);
                    continue;
                }

                ASSERT_ARE_EQUAL(DEVICE_TWIN_UPDATE_STATE, DEVICE_TWIN_UPDATE_PARTIAL, device_desired_data->update_state);
                Unlock(device_desired_data->lock);
                break;
            }
            Unlock(device_desired_data->lock);
        }
        ThreadAPI_Sleep(1000);
    }

    ASSERT_IS_TRUE(difftime(now_time, begin_operation) < MAX_CLOUD_TRAVEL_TIME, "Timeout waiting for twin message");

    // Unsubscribe
    _set_device_twin_callback(NULL, NULL);

    // Check results.
    if (Lock(device_desired_data->lock) != LOCK_OK)
    {
        ASSERT_FAIL("Lock failed");
    }
    else
    {
        // Reset final byte ($version) to match expected. Superfluous comparison.
        device_desired_data->cb_payload[device_desired_data->cb_payload_size - 1] = 0x00;
        ASSERT_ARE_EQUAL(char_ptr, expected_buffer, device_desired_data->cb_payload, "desired payload retrieved differs from expected");
        (void)Unlock(device_desired_data->lock);
    }

    // Cleanup
    free(expected_buffer);
    free(buffer);
    free(expected_desired_string);
    free(twin_data);
    IoTHubDeviceTwin_Destroy(serviceclient_devicetwin_handle);
    IoTHubServiceClientAuth_Destroy(iothub_serviceclient_handle);
    _device_desired_data_deinit(device_desired_data);
    _breakdown_test();
}

void dt_e2e_get_twin_async_CBOR_test(IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol, IOTHUB_ACCOUNT_AUTH_METHOD account_auth_method)
{
    IOTHUB_PROVISIONED_DEVICE* device_to_use = IoTHubAccount_GetDevice(iothub_accountinfo_handle, account_auth_method);
    _setup_test(device_to_use, protocol);

    OPTION_TWIN_CONTENT_TYPE_VALUE ct = OPTION_TWIN_CONTENT_TYPE_CBOR;
    _set_option(OPTION_TWIN_CONTENT_TYPE, &ct, "Cannot enable CBOR"); // Set prior to network I/O.

    bool is_cbor = true;
    _request_twin_and_wait_for_response(device_to_use, DEVICE_TWIN_UPDATE_COMPLETE, is_cbor);

    // Cleanup
    _breakdown_test();
}
