# Run a simple Device CBOR sample for C2D, Telemetry and Twin

## Introduction

This [sample](https://github.com/Azure/azure-iot-sdk-c/tree/master/iothub_client/samples/paho_iot_hub_cbor_c2d_telemetry_twin_sample/paho_iot_hub_cbor_c2d_telemetry_twin_sample.c) utilizes the Azure IoT Hub to get the device twin document, send a reported property message, and receive desired property messages all in CBOR. It also shows how to set an application-defined content type (such as CBOR) for either C2D or telemetry messaging, to be used with a coordinated service-side application. After 10 attempts to receive a message, the sample will exit. To run this sample, the MIT licensed [intel/tinycbor](https://github.com/intel/tinycbor) library must be installed. Please see the futher below for instructions. The Embedded C SDK is not dependent on ny particular CBOR library.

## Step 1: Prerequisites

You should have the following items ready before beginning the process:

-   [Prepare your development environment, IoT Hub, and Device](https://github.com/Azure/azure-iot-sdk-c/tree/master/iothub_client/samples#how-to-compile-and-run-the-samples)

## Step 2: Install Intel's tinycbor library.
Intel/tinycbor is [licenesed](https://github.com/intel/tinycbor/blob/master/LICENSE) under the MIT License.

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

    Select your device's "Device Twin" tab in the Azure Portal of your IoT Hub. Add one of the avilable desired properties along with a corresponding value of the supported value type to the `desired` section of the JSON. Select "Save" to update the twin document and send the desired property twin message to the device. The IoT Hub will translate the twin JSON into CBOR for the device to consume.

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

    Select your device's "Message to Device" tab in the Azure Portal for your IoT Hub. Under "Properties", enter `$.ct` for "Key", and `cbor` for "Value". Enter a message in the "Message Body" and select "Send Message" to send a message to your device.

    <b>IMPORTANT:</b> This sample only demonstrates how to set the expected content type for a C2D message on the device side. Only device-side implementation is shown; the corresponding service-side required implementation to use this feature is not part of this sample. The Azure Portal service-side application does not support CBOR translation for C2D messages, therefore any correctly formatted JSON message sent from the portal will not arrive to the device as correct CBOR.

- Telemetry:

    After receiving a message (C2D or twin desired property) or upon a message timeout, the sample will send a single telemetry message in CBOR. After 10 attempts to receive a message, the sample will exit.

    <b>IMPORTANT:</b> This sample only demonstrates how to set the expected content type for a Telemetry message on the device side. Only device-side implementation is shown; the corresponding service-side required implementation to use this feature is not part of this sample.
