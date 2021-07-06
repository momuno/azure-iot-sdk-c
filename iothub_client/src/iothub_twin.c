// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdbool.h>
#include <stdlib.h>

#include "iothub_twin.h"

static bool twin_request_options_get_current_version(
    IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE twin_request_options,
    int64_t* value)
{
    bool result = twin_request_options->_internal.is_current_version_set;
    if (result)
    {
        *value = twin_request_options->_internal.current_version;
    }

    return result;
}

static void twin_request_options_set_current_version(
    IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE twin_request_options,
    int64_t* value)
{
    if (!value)
    {
        twin_request_options->_internal.is_current_version_set = false;
        twin_request_options->_internal.current_version = 0;
    }
    else
    {
        twin_request_options->_internal.is_current_version_set = true;
        twin_request_options->_internal.current_version = *value;
    }
}

IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE IoTHubTwin_CreateRequestOptions(void)
{
    IOTHUB_TWIN_REQUEST_OPTIONS* twin_request_options;

    twin_request_options =
        (IOTHUB_TWIN_REQUEST_OPTIONS*)malloc(sizeof(IOTHUB_TWIN_REQUEST_OPTIONS));

    if (twin_request_options != NULL)
    {
        memset((void*)twin_request_options, 0, sizeof(IOTHUB_TWIN_REQUEST_OPTIONS));

        twin_request_options->get_current_version = twin_request_options_get_current_version;
        twin_request_options->set_current_version = twin_request_options_set_current_version;

        twin_request_options->_internal.is_current_version_set = false;
        twin_request_options->_internal.current_version = 0;
    }

    return twin_request_options;
}

void IoTHubTwin_DestroyRequestOptions(IOTHUB_TWIN_REQUEST_OPTIONS_HANDLE twin_request_options)
{
    if (twin_request_options)
    {
        free(twin_request_options);
    }
}

static bool twin_response_get_status(IOTHUB_TWIN_RESPONSE_HANDLE twin_response, int64_t* value)
{
    bool result = twin_response->_internal.is_status_set;
    if (result)
    {
        *value = twin_response->_internal.status;
    }

    return result;
}

static bool twin_response_get_version(IOTHUB_TWIN_RESPONSE_HANDLE twin_response, int64_t* value)
{
    bool result = twin_response->_internal.is_version_set;
    if (result)
    {
        *value = twin_response->_internal.version;
    }

    return result;
}

static void twin_response_set_status(IOTHUB_TWIN_RESPONSE_HANDLE twin_response, int64_t* value)
{
    if (!value)
    {
        twin_response->_internal.is_status_set = false;
        twin_response->_internal.status = 0;
    }
    else
    {
        twin_response->_internal.is_status_set = true;
        twin_response->_internal.status = *value;
    }
}

static void twin_response_set_version(IOTHUB_TWIN_RESPONSE_HANDLE twin_response, int64_t* value)
{
    if (!value)
    {
        twin_response->_internal.is_version_set = false;
        twin_response->_internal.version = 0;
    }
    else
    {
        twin_response->_internal.is_version_set = true;
        twin_response->_internal.version = *value;
    }
}

IOTHUB_TWIN_RESPONSE_HANDLE IoTHubTwin_CreateResponse(void)
{
    IOTHUB_TWIN_RESPONSE* twin_response;

    twin_response = (IOTHUB_TWIN_RESPONSE*)malloc(sizeof(IOTHUB_TWIN_RESPONSE));

    if (twin_response != NULL)
    {
        memset((void*)twin_response, 0, sizeof(IOTHUB_TWIN_RESPONSE));

        twin_response->get_status = twin_response_get_status;
        twin_response->set_status = twin_response_set_status;

        twin_response->get_version = twin_response_get_version;
        twin_response->set_version = twin_response_set_version;

        twin_response->_internal.is_status_set = false;
        twin_response->_internal.status = 0;

        twin_response->_internal.is_version_set = false;
        twin_response->_internal.version = 0;
    }

    return twin_response;
}

IOTHUB_TWIN_RESPONSE_HANDLE IoTHubTwin_CreateCopyResponse(IOTHUB_TWIN_RESPONSE_HANDLE twin_response)
{
    IOTHUB_TWIN_RESPONSE* copy_twin_response;

    copy_twin_response = IoTHubTwin_CreateResponse();

    if (twin_response != NULL)
    {
        copy_twin_response->_internal.is_status_set = twin_response->_internal.is_status_set;
        copy_twin_response->_internal.status = twin_response->_internal.status;

        copy_twin_response->_internal.is_version_set = twin_response->_internal.is_version_set;
        copy_twin_response->_internal.version = twin_response->_internal.version;
    }

    return copy_twin_response;
}

void IoTHubTwin_DestroyResponse(IOTHUB_TWIN_RESPONSE_HANDLE twin_response)
{
    if (twin_response)
    {
        free(twin_response);
    }
}
