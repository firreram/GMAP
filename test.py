import asyncio
import random
import logging
from bleak import BleakClient, BleakScanner

# Enable debug logging for bleak
logging.basicConfig()
logger = logging.getLogger(__name__)

def fuzz_data(length=10):
    return bytes(random.getrandbits(8) for _ in range(length))

async def on_disconnect(client):
    logger.info(f"Disconnected from {client.address}!")

async def keep_alive_task(client, char_uuid=None):
    """Periodically read or write to keep the connection alive."""
    while client.is_connected:
        try:
            if char_uuid:
                value = await client.read_gatt_char(char_uuid)
                logger.info(f"Keep-alive read from {char_uuid}: {value.hex()}")
            else:
                logger.info("No keep-alive characteristic specified")
        except Exception as e:
            logger.warning(f"Keep-alive operation failed: {e}")
        await asyncio.sleep(3.0)  # Short interval for S23

async def handle_notifications(handle, data):
    """Callback for notification data."""
    logger.info(f"Notification from handle {handle}: {data.hex()}")

async def main():
    timeout = 10.0
    print("Scanning...")
    devices = await BleakScanner.discover(timeout, return_adv=True)
    if not devices:
        print("No devices found!")
        return

    for i, (addr, (device, adv)) in enumerate(devices.items()):
        name = device.name or "Unknown"
        rssi = adv.rssi
        print(f"[{i}] {name} ({addr}, RSSI: {rssi}dBm)")

    index = input("Select device (or 'q' to quit): ")
    if index.lower() == 'q':
        return
    try:
        index = int(index)
        if index < 0 or index >= len(devices):
            raise ValueError("Invalid device index")
    except ValueError:
        print("Please enter a valid number")
        return

    devices_list = list(devices.items())
    address, (device, adv_data) = devices_list[index]
    print(f"Connecting to {device.name or address}")

    try:
        async with BleakClient(address, disconnected_callback=on_disconnect) as client:
            print("Connected!")
            if not client.is_connected:
                print("Connection failed!")
                return

            # Stabilize connection
            print("Waiting for device to stabilize...")
            await asyncio.sleep(3.0)  # Increased for S23

            if not client.is_connected:
                print("Disconnected before keep-alive!")
                return

            # Start keep-alive task early (before discovery)
            keep_alive_char_uuid = None  # Will be set later if found
            keep_alive = asyncio.create_task(keep_alive_task(client))

            print("Discovering services...")
            services = client.services  # Use property directly
            print("Services discovered!")

            if not client.is_connected:
                print("Disconnected after service discovery!")
                keep_alive.cancel()
                return

            # Try bonding (optional)
            try:
                await client.pair()
                print("Paired with device")
            except Exception as e:
                logger.warning(f"Pairing failed: {e}")

            # Enable notifications early
            heart_rate_char = "00002a37-0000-1000-8000-00805f9b34fb"
            notify_chars = []
            write_chars = []
            for service in services:
                for char in service.characteristics:
                    props = char.properties
                    if char.uuid == heart_rate_char and "notify" in props:
                        try:
                            await client.start_notify(char.uuid, handle_notifications)
                            print(f"Enabled notifications for {char.uuid}")
                        except Exception as e:
                            logger.warning(f"Failed to enable notifications for {char.uuid}: {e}")
                    if char.uuid == "00002a00-0000-1000-8000-00805f9b34fb" and "read" in props:
                        keep_alive_char_uuid = char.uuid

            # Update keep-alive task with characteristic if found
            if keep_alive_char_uuid:
                print(f"Using {keep_alive_char_uuid} for keep-alive")
                keep_alive.cancel()  # Stop placeholder task
                keep_alive = asyncio.create_task(keep_alive_task(client, keep_alive_char_uuid))

            print("Listing characteristics...")
            for service in services:
                print(f"Service: {service.uuid} -------------------------------")
                for char in service.characteristics:
                    props = char.properties
                    if "notify" in props or "indicate" in props:
                        notify_chars.append(char)
                        print(f"[] {char.uuid} - Notify/Indicate (Properties: {props})")
                    if "write" in props or "write-without-response" in props:
                        print(f"[{len(write_chars)}] {char.uuid} - Writable (Properties: {props})")
                        write_chars.append(char)
                    else:
                        print(f"[] {char.uuid} (Properties: {props})")
                    await asyncio.sleep(0.05)

            if not client.is_connected:
                print("Disconnected after listing characteristics!")
                keep_alive.cancel()
                return

            if not write_chars:
                print("No writable characteristics found!")
                keep_alive.cancel()
                return

            char_index = input("Select characteristic to fuzz: ")
            try:
                char_index = int(char_index)
                if char_index < 0 or char_index >= len(write_chars):
                    raise ValueError("Invalid characteristic index")
            except ValueError:
                print("Please enter a valid number")
                keep_alive.cancel()
                return

            target_char = write_chars[char_index]
            print(f"Selected characteristic: {target_char.uuid}")
            print(f"Properties: {target_char.properties}")

            # Test write
            if client.is_connected:
                print("Testing single write...")
                test_data = b'\x00'
                try:
                    await client.write_gatt_char(target_char.uuid, test_data, response="write" in target_char.properties)
                    print(f"Test write successful: {test_data.hex()}")
                except Exception as e:
                    print(f"Test write failed: {e}")
                    keep_alive.cancel()
                    return
            else:
                print("Disconnected before test write!")
                keep_alive.cancel()
                return

            iterations = int(input("Enter number of fuzzing iterations: "))
            max_data_len = int(input("Enter max data length: "))

            print(f"Fuzzing {target_char.uuid}...")
            for i in range(iterations):
                if not client.is_connected:
                    print("Disconnected during fuzzing!")
                    break
                data = fuzz_data(random.randint(1, max_data_len))
                print(f"Write #{i}: {data.hex()}")
                try:
                    await client.write_gatt_char(target_char.uuid, data, response="write" in target_char.properties)
                except Exception as e:
                    print(f"Error: {e}")

            # Clean up
            keep_alive.cancel()
            for char in notify_chars:
                try:
                    await client.stop_notify(char.uuid)
                except Exception:
                    pass

    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Quit...")