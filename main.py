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

# Tshark device permission: sudo visudo -> seclab ALL=(ALL) NOPASSWD: /usr/bin/tshark

filename = "ble_fuzzer.log"  # default filename
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(filename),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global state to track the selected device and disconnection flag
device_state = {"device": None, "name": "none", "disconnected": False}

def change_log_file(new_filename):
    """Change the log file to a new filename."""
    global filename, logger
    if not new_filename:
        logger.warning("No filename provided for log file change")
        print("Please provide a valid filename.")
        return
    filename = new_filename
    logger.info(f"Switching log file to {filename}")
    # Remove existing file handler
    for handler in logger.handlers[:]:  # Copy to avoid modifying while iterating
        if isinstance(handler, logging.FileHandler):
            logger.removeHandler(handler)
            handler.close()
    # Add new file handler
    new_handler = logging.FileHandler(filename)
    new_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(new_handler)
    logger.info(f"Log file switched to {filename}")
    print(f"Log file switched to {filename}")

async def progress_bar(duration):
    for _ in tqdm(range(duration), desc="Scanning", unit="s"):
        await asyncio.sleep(1)

def on_disconnect(client):
    global device_state
    logger.info(f"Connection closed ({client.address})")
    device_state["disconnected"] = True
    device_state["device"] = None
    device_state["name"] = "none"

async def discover_devices():
    timeout = 30.0
    logger.info("Starting device discovery")
    scanner_task = asyncio.create_task(BleakScanner.discover(timeout=timeout))
    progress_task = asyncio.create_task(progress_bar(int(timeout)))

    devices = await scanner_task
    await progress_task  # Ensure the bar finishes
    if not devices:
        logger.info("No devices found")
        print("No devices found.")
    for device in devices:
        name = device.name if device.name and device.name.replace('-', '') != device.address.replace(':', '') else 'Unknown'
        logger.info(f"Found device: {name} ({device.address})")
        print(f"Device: {name} ({device.address})")
    return None

async def find_device(device_name=None):
    global device_state
    if device_name:
        logger.info(f"Attempting to find device: {device_name}")
        print("Connecting...")
        device = await BleakScanner.find_device_by_name(device_name, timeout=10.0)
        if device:
            logger.info(f"Found device: {device.name} ({device.address})")
            print(f"Found device: {device.name} ({device.address})")
            device_state["device"] = device
            device_state["name"] = device.name if device.name and device.name.replace('-', '') != device.address.replace(':', '') else 'Unknown'
            device_state["disconnected"] = False
        else:
            logger.warning("Device not found")
            print("Device not found.")
            device_state["device"] = None
            device_state["name"] = "none"
        return device
    else:
        logger.warning("No device name provided")
        print("Insert a device name to connect")
        return None

async def connect_and_list(device):
    """Connect to the BLE device and interact with its GATT services."""
    global device_state
    logger.info(f"Connecting to {device_state['name']} ({device.address})")
    try:
        print("Connecting...")
        async with BleakClient(device, timeout=20.0) as client:
            try:
                logger.info(f"Connected to {device_state['name']}")
                print(f"Connected to {device_state['name']}")
                # Discover services and characteristics
                services = client.services
                if services:
                    logger.info("Listing services and characteristics")
                    print("Services and Characteristics:")
                    for service in services:
                        print(f" Service: {service.description}:{service.uuid}, Handle: {service.handle} +++++++++++++++++++++++++")
                        logger.info(f"Service: {service.description}, UUID: {service.uuid}, Handle: {service.handle}")
                        for char in service.characteristics:
                            print(f"    Characteristic: {char.description}:{char.uuid} ~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                            print(f"        Declaration: {char.properties}")
                            print(f"        Handle: {char.handle}")
                            logger.info(f"Characteristic: {char.description}, UUID: {char.uuid}, Properties: {char.properties}, Handle: {char.handle}")
                            for desc in char.descriptors:
                                print(f"            Descriptor: {desc.description}:{desc.uuid}, Handle: {desc.handle}")
                                logger.info(f"Descriptor: {desc.description}, UUID: {desc.uuid}, Handle: {desc.handle}")
                else:
                    logger.info("No advertised GATT services")
                    print("No advertised GATT services.")
            except BleakError as e:
                logger.error(f"BLE error: {e}")
                print(f"BLE error: {e}")
                device_state["device"] = None
                device_state["name"] = "none"
            except Exception as e:
                logger.error(f"Error: {e}")
                print(f"Error: {e}")
                device_state["device"] = None
                device_state["name"] = "none"
    except Exception as e:
        logger.error(f"Connection error: {e}")
        print(f"Connection error: {e}")
        device_state["device"] = None
        device_state["name"] = "none"

async def fuzz_handles_read_write_subroutine(device, min_handle, max_handle, handle_range, single_connection, write_fuzzing, payload_size):
    """Fuzz handles by reading and optionally writing random data."""
    global device_state
    payload_random = payload_size == 0 # 0 means random payload size
    mode = "read/write" if write_fuzzing else "read-only"
    logger.info(f"Fuzzing {len(handle_range)} handles ({min_handle} to {max_handle}) in {mode} mode")
    print(f"Fuzzing {len(handle_range)} handles ({min_handle} to {max_handle}) in {mode} mode")
    results = []
    current_handle = min_handle

    # Start Wireshark/tshark capture
    pcap_file = f"/tmp/ble_fuzzer_rw_{int(time.time())}.pcap"
    absolute_pcap = os.path.abspath(pcap_file)
    tshark_cmd = [
        "sudo", "tshark",
        "-i", "bluetooth0",
        "-w", absolute_pcap
    ]
    tshark_process = None
    try:
        logger.info(f"Starting Wireshark capture to {absolute_pcap}")
        print(f"Starting Wireshark capture to {absolute_pcap}")
        tshark_process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        await asyncio.sleep(1)
        if tshark_process.poll() is not None:
            stderr_output = tshark_process.stderr.read()
            logger.error(f"tshark failed to start: {stderr_output}")
            print(f"Error: tshark failed to start: {stderr_output}")
            tshark_process = None
    except FileNotFoundError:
        logger.error("tshark or sudo not found. Please install Wireshark and ensure sudo is configured.")
        print("Error: tshark or sudo not found. Please install Wireshark and ensure sudo is configured.")
        tshark_process = None
    except PermissionError as e:
        logger.error(f"Failed to start tshark: Permission denied. Ensure sudo permissions or run script with sudo.")
        print(f"Error: Failed to start tshark: Permission denied. Ensure sudo permissions or run script with sudo.")
        tshark_process = None
    except Exception as e:
        logger.error(f"Failed to start tshark: {e}")
        print(f"Error: Failed to start tshark: {e}")
        tshark_process = None

    try:
        if single_connection:
            retries = 3
            while current_handle <= max_handle:
                try:
                    print("Connecting...")
                    async with BleakClient(device, timeout=20.0, disconnected_callback=on_disconnect) as client:
                        device_state["disconnected"] = False
                        logger.info("Established single connection for fuzzing")
                        for handle in tqdm(range(current_handle, max_handle + 1), desc="Fuzzing handles", unit="handle", initial=current_handle - 1, total=max_handle):
                            if device_state["disconnected"]:
                                logger.warning(f"Device disconnected at handle {handle}. Stopping fuzzing.")
                                print(f"Warning: Device disconnected at handle {handle}. Stopping fuzzing.")
                                raise BleakError("Client disconnected")
                            result = {"handle": handle, "read": None, "write": None}
                            # Try reading
                            try:
                                data = await client.read_gatt_char(handle)
                                result["read"] = f"Succeeded (data: {data.hex()})"
                                logger.info(f"Handle {handle}({hex(handle)}): Read succeeded (data: {data.hex()})")
                                print(f"Handle {handle}({hex(handle)}): Read succeeded (data: {data.hex()})")
                            except BleakError as e:
                                result["read"] = f"Failed ({e})"
                                logger.info(f"Handle {handle}({hex(handle)}): Read failed ({e})")
                                print(f"Handle {handle}({hex(handle)}): Read failed ({e})")
                            # Try writing if enabled
                            if write_fuzzing:
                                payload_size = payload_size if not payload_random else random.randint(1, 20)
                                payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
                                try:
                                    await client.write_gatt_char(handle, payload, response=True)
                                    result["write"] = f"Succeeded (payload: {payload.hex()})"
                                    logger.info(f"Handle {handle}({hex(handle)}): Write succeeded (payload: {payload.hex()})")
                                    print(f"Handle {handle}({hex(handle)}): Write succeeded (payload: {payload.hex()})")
                                except BleakError as e:
                                    result["write"] = f"Failed ({e})"
                                    logger.info(f"Handle {handle}({hex(handle)}): Write failed ({e})")
                                    print(f"Handle {handle}({hex(handle)}): Write failed ({e})")
                            results.append(result)
                            await asyncio.sleep(0.1)
                            current_handle = handle + 1
                            retries = 3
                        if not device_state["disconnected"]:
                            break
                except BleakError as e:
                    logger.error(f"Connection error at handle {current_handle}: {e}")
                    print(f"Connection error at handle {current_handle}: {e}")
                    if retries > 0:
                        retries -= 1
                        logger.info(f"Retrying connection ({retries} retries left)")
                        await asyncio.sleep(1)
                    else:
                        logger.error("Max retries reached. Stopping fuzzing.")
                        print("Max retries reached. Stopping fuzzing.")
                        break
        else:
            for handle in tqdm(handle_range, desc="Fuzzing handles", unit="handle"):
                try:
                    async with BleakClient(device, timeout=20.0, disconnected_callback=on_disconnect) as client:
                        result = {"handle": handle, "read": None, "write": None}
                        # Try reading
                        try:
                            data = await client.read_gatt_char(handle)
                            result["read"] = f"Succeeded (data: {data.hex()})"
                            logger.info(f"Handle {handle}({hex(handle)}): Read succeeded (data: {data.hex()})")
                            print(f"Handle {handle}({hex(handle)}): Read succeeded (data: {data.hex()})")
                        except BleakError as e:
                            result["read"] = f"Failed ({e})"
                            logger.info(f"Handle {handle}({hex(handle)}): Read failed ({e})")
                            print(f"Handle {handle}({hex(handle)}): Read failed ({e})")
                        # Try writing if enabled
                        if write_fuzzing:
                            # Determine payload length
                            payload_size = payload_size if payload_size > 0 else random.randint(1, 20)
                            payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
                            try:    
                                await client.write_gatt_char(handle, payload, response=True)
                                result["write"] = f"Succeeded (payload: {payload.hex()})"
                                logger.info(f"Handle {handle}({hex(handle)}): Write succeeded (payload: {payload.hex()})")
                                print(f"Handle {handle}({hex(handle)}): Write succeeded (payload: {payload.hex()})")
                            except BleakError as e:
                                result["write"] = f"Failed ({e})"
                                logger.info(f"Handle {handle}({hex(handle)}): Write failed ({e})")
                                print(f"Handle {handle}({hex(handle)}): Write failed ({e})")
                        results.append(result)
                        await asyncio.sleep(0.1)
                except BleakError as e:
                    logger.error(f"Connection error for handle {handle}: {e}")
                    print(f"Connection error for handle {handle}: {e}")
                except Exception as e:
                    logger.error(f"Error for handle {handle}: {e}")
                    print(f"Error for handle {handle}: {e}")
    finally:
        if tshark_process:
            try:
                logger.info("Terminating Wireshark capture")
                print("Terminating Wireshark capture")
                tshark_process.terminate()
                tshark_process.wait(timeout=10)
                logger.info(f"Wireshark capture stopped. Saved to {absolute_pcap}")
                print(f"Wireshark capture stopped. Saved to {absolute_pcap}")
                if os.path.exists(absolute_pcap):
                    logger.info(f"Confirmed PCAP file exists: {absolute_pcap}")
                    print(f"Confirmed PCAP file exists: {absolute_pcap}")
                else:
                    logger.error(f"PCAP file not created: {absolute_pcap}")
                    print(f"Error: PCAP file not created: {absolute_pcap}")
            except subprocess.TimeoutExpired:
                logger.warning("tshark did not terminate gracefully. Sending SIGINT.")
                print("Warning: tshark did not terminate gracefully. Sending SIGINT.")
                os.kill(tshark_process.pid, signal.SIGINT)
                try:
                    tshark_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning("tshark still running. Killing process.")
                    print("Warning: tshark still running. Killing process.")
                    tshark_process.kill()
                logger.info(f"Wireshark capture stopped. Saved to {absolute_pcap}")
                print(f"Wireshark capture stopped. Saved to {absolute_pcap}")
                if os.path.exists(absolute_pcap):
                    logger.info(f"Confirmed PCAP file exists: {absolute_pcap}")
                    print(f"Confirmed PCAP file exists: {absolute_pcap}")
                else:
                    logger.error(f"PCAP file not created: {absolute_pcap}")
                    print(f"Error: PCAP file not created: {absolute_pcap}")
            except Exception as e:
                logger.error(f"Error stopping tshark: {e}")
                print(f"Error stopping tshark: {e}")

    return results

async def fuzz_handles_read_write(device):
    """Fuzz handles by reading and optionally writing random data."""
    global device_state
    if not device:
        logger.warning("No device selected. Please connect to a device first.")
        print("No device selected. Please connect to a device first.")
        return

    logger.info(f"Connecting to {device_state['name']} for read/write fuzzing")
    print(f"Connecting to {device_state['name']} for read/write fuzzing")

    # Step 1: Try to get the maximum handle by scanning services
    max_handle = 0
    min_handle = 1
    try:
        async with BleakClient(device, timeout=20.0) as client:
            services = client.services
            for service in services:
                for char in service.characteristics:
                    max_handle = max(max_handle, char.handle)
                    for desc in char.descriptors:
                        max_handle = max(max_handle, desc.handle)
            if max_handle > 0:
                logger.info(f"Maximum handle found: {max_handle}")
                restrict_range = input(f"Maximum handle found: {max_handle}, test this range? (y/n): ") == 'y'
                if not restrict_range: #do not restrict
                    logger.info("Using full 16-bit range (1 to 65535).")
                    max_handle = 65535
                else:
                    logger.info(f"Using handle range: 1 to {max_handle}")
                    print(f"Using handle range: 1 to {max_handle}")
            else:
                logger.info("No characteristics or descriptors found.")
                print("No characteristics or descriptors found.")
    except BleakError as e:
        logger.error(f"Error discovering services: {e}")
        print(f"Error discovering services: {e}")
    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"Error: {e}")

    # Step 2: Set handle range
    if max_handle == 0:
        logger.info("Could not determine maximum handle.")
        if input("Could not determine maximum handle. Use full 16-bit range (1 to 65535)? (y/n): ") != 'y':
            handle_range_input = input("Enter handle range (1 to 65535) separated by space (e.g., 1 100): ")
            handle_range_input = list(map(int, handle_range_input.split()))
            if handle_range_input[0] < 1 or handle_range_input[1] > 65535 or handle_range_input[0] > handle_range_input[1]:
                logger.error("Invalid handle range. Using full 16-bit range (1 to 65535).")
                print("Invalid handle range. Using full 16-bit range (1 to 65535).")
                min_handle = 1
                max_handle = 65535
            else:
                logger.info(f"Using handle range: {handle_range_input[0]} to {handle_range_input[1]}")
                print(f"Using handle range: {handle_range_input[0]} to {handle_range_input[1]}")
                min_handle = handle_range_input[0]
                max_handle = handle_range_input[1]
        else:
            max_handle = 65535
    handle_range = range(min_handle, max_handle + 1)

    # Step 3: Ask for connection mode
    single_connection = input("Use single connection for all handles?(Faster but more unstable) (y/n): ").lower().strip() == 'y'
    logger.info(f"Using {'single connection' if single_connection else 'per-handle connections'} mode")

    # Step 4: Ask for write fuzzing
    write_fuzzing = input("Enable write fuzzing with random data?(Intrusive) (y/n): ").lower().strip() == 'y'
    logger.info(f"{'Enabling' if write_fuzzing else 'Disabling'} write fuzzing")
    payload_size = 8
    if write_fuzzing:
        payload_size_input = input("Enter payload size for random data (bytes, 0 for random, default 8)(max 20, but more possible): ").strip()
        payload_size = int(payload_size_input) if payload_size_input.isdigit() else 8
        logger.info(f"Payload size for random data: {payload_size_input if payload_size > 0 else 'random'}")
    # Step 5: Fuzz handles
    results = await fuzz_handles_read_write_subroutine(device, min_handle, max_handle, handle_range, single_connection, write_fuzzing, payload_size)

    # Step 6: Summarize results
    logger.info("Fuzzing complete")
    print("\nFuzzing complete.")
    readable_handles = [r["handle"] for r in results if r["read"] and r["read"].startswith("Succeeded")]
    writable_handles = [r["handle"] for r in results if r["write"] and r["write"].startswith("Succeeded")]
    if readable_handles or writable_handles:
        if readable_handles:
            logger.info(f"Found {len(readable_handles)} readable handles: {readable_handles}")
            print(f"Found {len(readable_handles)} readable handles: {readable_handles}")
        if writable_handles:
            logger.info(f"Found {len(writable_handles)} writable handles: {writable_handles}")
            print(f"Found {len(writable_handles)} writable handles: {writable_handles}")
    else:
        logger.info("No readable or writable handles found")
        print("No readable or writable handles found.")

def print_menu():  # Menu
    print('\n' * 50)
    print(30 * "-", "Welcome to Simple BLE Fuzzer", 30 * "-")
    print("1. Scan for all BLE devices")
    print("2. Connect to a BLE device")
    print("3. View all characteristics")
    print("4. Start fuzzer")
    print("5. Change logfile")
    print("6. Exit")
    print(80 * "-")

async def main():
    global device_state
    loop = True
    while loop:
        print_menu()
        choice = input(f"[{device_state['name']}] Enter your choice [1-6]: ")
        if choice == "1":
            await discover_devices()
        elif choice == "2":
            dev_name = input("Insert device name: ")
            if dev_name != "":
                device = await find_device(dev_name)
                if not device:
                    print("Device not found.")
            else:
                print("Insert a name")
        elif choice == "3":
            if not device_state["device"]:
                print("Select a device first")
            else:
                print(f"[{device_state['name']}] Getting services...")
                await connect_and_list(device_state["device"])
        elif choice == "4":
            if not device_state["device"]:
                print("Select a device first")
            else:
                print(f"[{device_state['name']}] Starting handle scanner...")
                await fuzz_handles_read_write(device_state["device"])
        elif choice == "5":
            new_filename = input("Insert new log filename: ")
            change_log_file(new_filename)
        elif choice == "6":
            print("Quit...")
            loop = False
        else:
            print("Invalid choice")
            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Program terminated by user")
        print()
        print("Quit...")