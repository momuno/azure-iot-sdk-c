// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/** @file   iothub_twin.h
*   @brief  The @c IoTHub_Twin component encapsulates all twin message related information that can
*           be transferred or received by an IoT hub client.
*/

#ifndef IOTHUB_TWIN_H
#define IOTHUB_TWIN_H

#include <stdbool.h>
#include <stdint.h>

#include "azure_macro_utils/macro_utils.h"

#include "umock_c/umock_c_prod.h"

#ifdef __cplusplus
#include <cstddef>
extern "C"
{
#endif


#ifndef IOTHUB_TWIN_REQUEST_OPTIONS_TYPE
typedef struct IOTHUB_TWIN_REQUEST_OPTIONS_TAG* IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE;
#define IOTHUB_TWIN_REQUEST_OPTIONS_TYPE
#endif
#ifndef IOTHUB_TWIN_RESPONSE_TYPE
typedef struct IOTHUB_TWIN_RESPONSE_TAG* IOTHUB_TWIN_RESPONSE_HANDLE;
#define IOTHUB_TWIN_RESPONSE_TYPE
#endif

/**
 * @brief  GET twin request options
 */
typedef bool(*IOTHUB_TWIN_REQUEST_OPTIONS_GET_INT64)(IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE twin_request_options, int64_t* value);
typedef void(*IOTHUB_TWIN_REQUEST_OPTIONS_SET_INT64)(IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE twin_request_options, int64_t* value);

typedef struct IOTHUB_TWIN_REQUEST_OPTIONS_TAG
{
    /**
     * @brief Get current_version for @c IOTHUB_TWIN_REQUEST_OPTIONS
     *
     * @param twin_request_options  Pointer to self.
     * @param value                 Value of current_version.
     * @return true if current_version has been set.
     * @return false if current_version has not been set. This means the option not used.
     */
    IOTHUB_TWIN_REQUEST_OPTIONS_GET_INT64 get_current_version;

    /**
     * @brief Set current_version for @c IOTHUB_TWIN_REQUEST_OPTIONS
     *
     * @param twin_request_options  Pointer to self.
     * @param value                 Pointer to value to set the current_version.
     *                              May be NULL if option to not be used.
     *
     * @note  The device's current version can be used to request a twin section. If the IoT Hub's
     *        current version matches this value, no payload will be sent. Otherwise, the IoT Hub's
     *        current version of the requested twin section will be sent. If this option is
     *        AZ_SPAN_EMPTY, the IoT Hub's current version of the requested twin section will be
     *        sent.
     * @note  Valid range is [1, 9223372036854775807]. Default is AZ_SPAN_EMPTY.
     * @note  This property is optional.
     **/
    IOTHUB_TWIN_REQUEST_OPTIONS_SET_INT64 set_current_version;

    struct
    {
        bool is_current_version_set;
        int64_t current_version;
    }_internal;

}IOTHUB_TWIN_REQUEST_OPTIONS;

/**
 * @brief Constructor for @c IOTHUB_TWIN_REQUEST_OPTIONS
 *
 * @return IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE
 */
MOCKABLE_FUNCTION(, IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE, IoTHubTwin_CreateRequestOptions);

/**
 * @brief Destructor for @c IOTHUB_TWIN_REQUEST_OPTIONS
 *
 * @param twin_request_options
 */
MOCKABLE_FUNCTION(, void, IoTHubTwin_DestroyRequestOptions, IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE, twin_request_options);


/**
 * @brief  Get twin response
 */
typedef bool(*IOTHUB_TWIN_RESPONSE_OPTIONS_GET_INT64)(IOTHUB_TWIN_RESPONSE_HANDLE twin_response, int64_t* value);

typedef struct IOTHUB_TWIN_RESPONSE_TAG
{
    /**
     * @brief Get status for @c IOTHUB_TWIN_RESPONSE
     *
     * @param twin_response  Pointer to self.
     * @param value          Value of version from twin response.
     * @return true if version has been set.
     * @return false if version has not been set.
     */
    IOTHUB_TWIN_RESPONSE_OPTIONS_GET_INT64 get_status;

    /**
     * @brief Get version for @c IOTHUB_TWIN_RESPONSE
     *
     * @param twin_response  Pointer to self.
     * @param value          Value of status from twin response.
     * @return true if status has been set.
     * @return false if status has not been set.
     */
    IOTHUB_TWIN_RESPONSE_OPTIONS_GET_INT64 get_version;

    struct
    {
        bool is_status_set;
        bool is_version_set;

        int64_t status;
        int64_t version;

    }_internal;
}IOTHUB_TWIN_RESPONSE;

/**
 * @brief Constructor for @c IOTHUB_TWIN_RESPONSE
 *
 * @return IOTHUB_TWIN_RESPONSE_HANDLE
 */
MOCKABLE_FUNCTION(, IOTHUB_TWIN_RESPONSE_HANDLE, IoTHubTwin_CreateResponse);

/**
 * @brief Copy constructor for @c IOTHUB_TWIN_RESPONSE
 *
 * @return IOTHUB_TWIN_RESPONSE_HANDLE
 */
MOCKABLE_FUNCTION(, IOTHUB_TWIN_RESPONSE_HANDLE, IoTHubTwin_CreateCopyResponse, IOTHUB_TWIN_RESPONSE_HANDLE, twin_response);

/**
 * @brief Destructor for @c IOTHUB_TWIN_RESPONSE
 *
 * @param twin_response
 */
MOCKABLE_FUNCTION(, void, IoTHubTwin_DestroyResponse, IOTHUB_TWIN_RESPONSE_HANDLE, twin_response);

#ifdef __cplusplus
}
#endif

#endif /* IOTHUB_TWIN_H */
