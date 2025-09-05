import asyncio
import random
import logging
import subprocess
import time
import os
import signal
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from tqdm.asyncio import tqdm

# Global state to track the selected device and disconnection flag
device_state = {"device": None, "name": "none", "disconnected": False}

async def find_device(device_name=None):
    global device_state
    if device_name:
        print("Connecting...")
        device = await BleakScanner.find_device_by_name(device_name, timeout=10.0)
        if device:
            print(f"Found device: {device.name} ({device.address})")
            device_state["device"] = device
            device_state["name"] = device.name if device.name and device.name.replace('-', '') != device.address.replace(':', '') else 'Unknown'
            device_state["disconnected"] = False
        else:
            print("Device not found.")
            device_state["device"] = None
            device_state["name"] = "none"
        return device
    else:
        print("Insert a device name to connect")
        return None

async def main():
    dev_name = input("Insert device name: ")
    if dev_name != "":
        device = await find_device(dev_name)
        if not device:
            print("Device not found.")
    else:
        print("Insert a name")
    print("Sending a single read command")
    async with BleakClient(device) as client:
        try:
            # Replace with the actual characteristic UUID
            characteristic_handle = 1234
            data = await client.read_gatt_char(characteristic_handle)
            print(f"Data received: {data}")
        except BleakError as e:
            print(f"Error reading characteristic: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")
    print("Disconnecting...")
    await asyncio.sleep(1)
    print("Disconnected.")
    print("Sending a single write command")
    async with BleakClient(device) as client:
        try:
            # Replace with the actual characteristic UUID and data to write+
            characteristic_handle = 1234
            data_to_write = b'\xca\xfe\xba\xbe\xff\xff\xff\xff'  # Example data to write
            await client.write_gatt_char(characteristic_handle, data_to_write)
            print(f"Data written: {data_to_write}")
        except BleakError as e:
            print(f"Error writing characteristic: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")
    print("Disconnecting...")
    await asyncio.sleep(1)
    print("Disconnected.")
    print("Sending a single read command, existing handle")
    async with BleakClient(device) as client:
        try:
            # Replace with the actual characteristic UUID
            characteristic_handle = int(0x8a)
            data = await client.read_gatt_char(characteristic_handle)
            print(f"Data received: {data}")
        except BleakError as e:
            print(f"Error reading characteristic: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")
    print("Program finished.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print()
        print("Quit...")