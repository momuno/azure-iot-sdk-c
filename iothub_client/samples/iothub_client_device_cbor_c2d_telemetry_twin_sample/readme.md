# Run a simple Device CBOR sample for C2D, Telemetry and Twin

## Introduction

This [sample](https://github.com/Azure/azure-iot-sdk-c/tree/master/iothub_client/samples/paho_iot_hub_cbor_c2d_telemetry_twin_sample/paho_iot_hub_cbor_c2d_telemetry_twin_sample.c) utilizes the Azure IoT Hub to get the device twin document, send a reported property message, and receive desired property messages all in CBOR. It also shows how to set the content type system property for C2D or telemetry messaging. After 10 attempts to receive a message, the sample will exit.

To run this sample, Intel's MIT licensed [TinyCBOR](https://github.com/intel/tinycbor) library must be installed. Please see below for instructions. The Embedded C SDK is not dependent on any particular CBOR library.

## Step 1: Prerequisites

You should have the following items ready before beginning the process:

-   [Prepare your development environment, IoT Hub, and Device](https://github.com/Azure/azure-iot-sdk-c/tree/master/iothub_client/samples#how-to-compile-and-run-the-samples)

## Step 2: Install Intel's tinycbor library.
Intel's TinyCBOR is [licenesed](https://github.com/intel/tinycbor/blob/master/LICENSE) under the MIT License.

Linux:

```bash
git clone https://github.com/intel/tinycbor.git
cd tinycbor
git checkout v0.5.3
make
sudo make install
```

Windows:

1.  Open the appropriate Visual Studio command prompt and install intel/tinycbor.

    - x86 system: Developer Command Prompt for Visual Studio.
    - x64 system: x64 Native Tools Command Prompt for Visual Studio.

    ```
    git clone https://github.com/intel/tinycbor.git
    cd tinycbor
    git checkout v0.5.3
    NMAKE /F Makefile.nmake
    ```

2.  Open PowerShell and update the Path environment variable.

    ```powershell
    $env:Path="$env:Path;<FULL PATH to tinycbor>"
    ```

<a name="Step-2-Build"></a>

## Step 3: Build and Run the sample

Follow [these instructions](https://github.com/Azure/azure-iot-sdk-c/blob/master/doc/devbox_setup.md) to build and run the sample for Linux or Windows.

### How to interact with the CBOR sample

- Device Twin:

    A property named `device_count` is supported for this sample.

    To send a device twin desired property message, select your device's "Device Twin" tab in the Azure Portal of your IoT Hub. Add one of the avilable desired properties along with a corresponding value of the supported value type to the `desired` section of the twin JSON. Select "Save" to update the twin document and send the twin message to the device. The IoT Hub will translate the twin JSON into CBOR for the device to consume and decode.

    ```json
    "properties": {
        "desired": {
            "change_oil_remainder": true,
            "state": {
                "max_speed": 200,
                "software_version": 4,
            }
        }
    }
    ```

    No other property names sent in a desired property message are supported.

- Cloud-to-Device Messaging:

   To send a C2D message, select your device's "Message to Device" tab in the Azure Portal for your IoT Hub. Under "Properties", enter the SDK-defined content type system property name `$.ct` for "Key", and the application-defined value `application/cbor` for "Value". This value must be agreed upon between the device and service side applications to use the content type system property for C2D messaging. Enter a message in the "Message Body" and select "Send Message". The Key and Value will appear as a URL-encoded key-value pair appended to the topic: `%24.ct=application%2Fcbor`.

    - NOTE: The Azure Portal will NOT translate a JSON formatted message into CBOR, nor will it encode the message in binary. Therefore, this sample only demonstrates how to parse the topic for the content type system property. It is up to the service application to encode correctly formatted CBOR (or other specified content type) and the device application to correctly decode it.

- Telemetry:

    The sample will automatically send CBOR formatted messages after each attempt to receive a C2D or desired property message. The SDK-defined content type system property name `$.ct` and the application-defined value `application/cbor` will appear as a URL-encoded key-value pair appended to the topic: `%24.ct=application%2Fcbor`. This value must be agreed upon between the device and service side applications to use the content type system property for Telemetry messaging.
