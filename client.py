import asyncio
import random
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

# Example UUIDs for a service and characteristic (replace with your nRF Connect configuration)
SERVICE_UUID = "0000180f-0000-1000-8000-00805f9b34fb"  # Battery Service
CHARACTERISTIC_UUID = "00002a19-0000-1000-8000-00805f9b34fb"  # Battery Level
NOTIFY_CHARACTERISTIC_UUID = "0000aaa1-0000-1000-8000-aabbccddeeff"

def fuzz_data(length=10):
    return bytes(random.getrandbits(8) for _ in range(length))

async def discover_device(device_name=None):
    """Scan for BLE devices and return the first matching device."""
    print("Scanning for BLE devices...")
    devices = await BleakScanner.discover()
    for device in devices:
        if device_name and device.name and device_name.lower() in device.name.lower():
            print(f"Found device: {device.name} ({device.address})")
            return device
        elif not device_name:
            print(f"Device: {device.name or 'Unknown'} ({device.address})")
    return None

async def connect_and_interact(device_address):
    """Connect to the BLE device and interact with its GATT services."""
    async with BleakClient(device_address, timeout=20.0) as client:
        try:
            print(f"Connected to {device_address}")
            
            # Discover services and characteristics
            services = await client.get_services()
            print("Services and Characteristics:")
            for service in services:
                print(f"  Service: {service.uuid}+++++++++++++++++++++++++")
                for char in service.characteristics:
                    print(f"    Characteristic: {char.uuid}, Properties: {char.properties}")
            
           # Check if SERVICE_UUID exists in discovered services
            if any(service.uuid == SERVICE_UUID for service in services):
                print(f"Service {SERVICE_UUID} found!")
            else:
                print(f"Service {SERVICE_UUID} not found.")
                
            # Read a characteristic (e.g., Battery Level)
            max_data_len=5
            for l in range(100):
                try:
                    value = await client.read_gatt_char(CHARACTERISTIC_UUID)
                    print(f"Read value from {CHARACTERISTIC_UUID}: {value.hex()}")
                except Exception as e:
                    print(f"Failed to read characteristic {CHARACTERISTIC_UUID}: {e}")
                try:
                    test_data = fuzz_data(l)
                    await client.write_gatt_char(CHARACTERISTIC_UUID, test_data, response=False)
                    print(f"Test write successful: {test_data.hex()}")
                except Exception as e:
                    print(f"Test write failed: {e}")

            # Enable notifications if supported
            if any(char.uuid == NOTIFY_CHARACTERISTIC_UUID for service in services for char in service.characteristics):
                def notification_handler(sender, data):
                    print(f"Notification from {sender}: {data.hex()}")
                
                await client.start_notify(NOTIFY_CHARACTERISTIC_UUID, notification_handler)
                print(f"Subscribed to notifications for {NOTIFY_CHARACTERISTIC_UUID}")
                await asyncio.sleep(20.0)  # Wait for notifications
                await client.stop_notify(NOTIFY_CHARACTERISTIC_UUID)
                print("Stopped notifications")

        except BleakError as e:
            print(f"BLE error: {e}")
        except Exception as e:
            print(f"Error: {e}")

async def main():
    # Step 1: Discover the Android device (replace 'nRF' with your device's advertised name)
    device = await discover_device("S23 di Manuel")
    if not device:
        print("Device not found. Please ensure nRF Connect is advertising.")
        return

    # Step 2: Connect and interact with the GATT server
    await connect_and_interact(device.address)

if __name__ == "__main__":
    asyncio.run(main())