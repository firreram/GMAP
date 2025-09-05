import asyncio
import random
import logging
import subprocess
import time
import os
import signal
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.logging import RichHandler
import uuid


GMAP_logo = """
      ___           ___           ___           ___
     /\  \         /\__\         /\  \         /\  \    
    /::\  \       /::|  |       /::\  \       /::\  \   
   /:/\:\  \     /:|:|  |      /:/\:\  \     /:/\:\  \  
  /:/  \:\  \   /:/|:|__|__   /::\~\:\  \   /::\~\:\  \ 
 /:/__/_\:\__\ /:/ |::::\__\ /:/\:\ \:\__\ /:/\:\ \:\__\ 
 \:\  /\ \/__/ \/__/~~/:/  / \/__\:\/:/  / \/__\:\/:/  /
  \:\ \:\__\         /:/  /       \::/  /       \::/  / 
   \:\/:/  /        /:/  /        /:/  /         \/__/  
    \::/  /        /:/  /        /:/  /                 
     \/__/         \/__/         \/__/                  

"""
        


# Configure rich console
console = Console()

#default interface
bt_interface = "bluetooth0"

# Configure logging with rich
filename = "ble_fuzzer.log"  # default filename
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(filename)
    ]
)
logger = logging.getLogger(__name__)

# Global state
device_state = {"device": None, "name": "none", "disconnected": False}

def change_log_file(new_filename):
    """Change the log file to a new filename."""
    global filename, logger
    if not new_filename:
        logger.warning("No filename provided for log file change")
        console.print("[yellow]Please provide a valid filename.[/yellow]")
        return
    filename = new_filename
    logger.info(f"Switching log file to {filename}")
    for handler in logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            logger.removeHandler(handler)
            handler.close()
    new_handler = logging.FileHandler(filename)
    new_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(new_handler)
    logger.info(f"Log file switched to {filename}")
    console.print(f"[green]Log file switched to {filename}[/green]")

async def discover_devices():
    timeout = 20.0
    logger.info("Starting device discovery")
    devices = {}
    try:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=int(timeout / 0.1))
            scanner_task = asyncio.create_task(
                BleakScanner.discover(timeout=timeout, return_adv=True)
            )
            for _ in range(int(timeout / 0.1)):
                await asyncio.sleep(0.1)
                progress.advance(task)
            devices = await scanner_task
    except BleakError as e:
        logger.error(f"BLE error during discovery: {e}")
        console.print(f"[red]BLE error during discovery: {e}[/red]")
        return None

    if not devices:
        logger.info("No devices found")
        console.print("[yellow]No devices found.[/yellow]")
        return None

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Name", style="cyan")
    table.add_column("Address", style="green")
    table.add_column("Advertisement Data", style="yellow", overflow="fold")
    for d in devices:
        (device, adv) = devices[d]
        name = device.name if device.name and device.name.replace('-', '') != device.address.replace(':', '') else 'Unknown'
        logger.info(f"Found device: {name} ({device.address})")
        table.add_row(name, device.address, str(adv))
    console.print(table)
    Prompt.ask("Press any key to continue", console=console)
    return None

async def find_device(device_name=None):
    global device_state
    if not device_name:
        logger.warning("No device name provided")
        console.print("[yellow]Please provide a device name.[/yellow]")
        return None
    logger.info(f"Attempting to find device: {device_name}")
    console.print(f"[cyan]Connecting to {device_name}...[/cyan]")
    device = await BleakScanner.find_device_by_name(device_name, timeout=10.0)
    if device:
        logger.info(f"Found device: {device.name} ({device.address})")
        console.print(f"[green]Found device: {device.name} ({device.address})[/green]")
        device_state["device"] = device
        device_state["name"] = device.name
        device_state["disconnected"] = False
    else:
        logger.warning("Device not found")
        console.print("[red]Device not found.[/red]")
        device_state["device"] = None
        device_state["name"] = "none"
    return device

async def connect_and_list(device):
    global device_state
    logger.info(f"Connecting to {device_state['name']} ({device.address})")
    console.print(f"[cyan]Connecting to {device_state['name']}...[/cyan]")
    try:
        async with BleakClient(device, timeout=20.0) as client:
            logger.info(f"Connected to {device_state['name']}")
            console.print(f"[green]Connected to {device_state['name']}[/green]")
            services = client.services
            if services:
                logger.info("Listing services and characteristics")
                console.print(Panel("[bold]Services and Characteristics[/bold]", style="bold blue"))
                for service in services:
                    console.print(f"[bold cyan]Service: {service.description} ({service.uuid})[/bold cyan], Handle: {service.handle}")
                    logger.info(f"Service: {service.description}, UUID: {service.uuid}, Handle: {service.handle}")
                    for char in service.characteristics:
                        console.print(f"  [cyan]Characteristic: {char.description} ({char.uuid})[/cyan], Properties: {char.properties}, Handle: {char.handle}")
                        logger.info(f"Characteristic: {char.description}, UUID: {char.uuid}, Properties: {char.properties}, Handle: {char.handle}")
                        for desc in char.descriptors:
                            console.print(f"      [dim]Descriptor: {desc.description} ({desc.uuid}), Handle: {desc.handle}[/dim]")
                            logger.info(f"Descriptor: {desc.description}, UUID: {desc.uuid}, Handle: {desc.handle}")
            else:
                logger.info("No advertised GATT services")
                console.print("[yellow]No advertised GATT services.[/yellow]")
        Prompt.ask("Press any key to continue...", console=console)
    except BleakError as e:
        logger.error(f"BLE error: {e}")
        console.print(f"[red]BLE error: {e}[/red]")
        device_state["device"] = None
        device_state["name"] = "none"
    except Exception as e:
        logger.error(f"Error: {e}")
        console.print(f"[red]Error: {e}[/red]")
        device_state["device"] = None
        device_state["name"] = "none"

async def fuzz_handles_read_write_subroutine(device, min_handle, max_handle, handle_range, single_connection, write_fuzzing, payload_size):
    global device_state
    payload_random = payload_size == 0
    mode = "read/write" if write_fuzzing else "read-only"
    logger.info(f"Fuzzing {len(handle_range)} handles ({min_handle} to {max_handle}) in {mode} mode")
    console.print(f"[cyan]Fuzzing {len(handle_range)} handles ({min_handle} to {max_handle}) in {mode} mode[/cyan]")
    results = []
    current_handle = min_handle

    # Start Wireshark/tshark capture
    pcap_file = f"/tmp/ble_fuzzer_rw_{int(time.time())}.pcap"
    absolute_pcap = os.path.abspath(pcap_file)
    tshark_cmd = ["tshark", "-i", bt_interface, "-w", absolute_pcap] #LET THE USER CHOOSE THE IFACE!!!
    tshark_process = None
    try:
        logger.info(f"Starting Wireshark capture to {absolute_pcap}")
        console.print(f"[cyan]Starting Wireshark capture to {absolute_pcap}[/cyan]")
        tshark_process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        await asyncio.sleep(1)
        if tshark_process.poll() is not None:
            stderr_output = tshark_process.stderr.read()
            logger.error(f"tshark failed to start: {stderr_output}")
            console.print(f"[red]Error: tshark failed to start: {stderr_output}[/red]")
            tshark_process = None
    except Exception as e:
        logger.error(f"Failed to start tshark: {e}")
        console.print(f"[red]Error: Failed to start tshark: {e}[/red]")
        tshark_process = None

    try:
        if single_connection:
            retries = 3
            while current_handle <= max_handle:
                try:
                    console.print("[cyan]Connecting...[/cyan]")
                    async with BleakClient(device, timeout=20.0, disconnected_callback=lambda client: on_disconnect(client)) as client:
                        device_state["disconnected"] = False
                        logger.info("Established single connection for fuzzing")
                        with Progress(
                            TextColumn("[progress.description]{task.description}"),
                            BarColumn(),
                            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                            console=console
                        ) as progress:
                            task = progress.add_task("[cyan]Fuzzing handles...", total=max_handle - min_handle + 1)
                            for handle in range(current_handle, max_handle + 1):
                                if device_state["disconnected"]:
                                    logger.warning(f"Device disconnected at handle {handle}. Stopping fuzzing.")
                                    console.print(f"[yellow]Warning: Device disconnected at handle {handle}. Stopping fuzzing.[/yellow]")
                                    raise BleakError("Client disconnected")
                                result = {"handle": handle, "read": None, "write": None}
                                try:
                                    data = await client.read_gatt_char(handle)
                                    result["read"] = f"Succeeded (data: {data.hex()})"
                                    logger.info(f"Handle {handle}({hex(handle)}): Read succeeded (data: {data.hex()})")
                                    console.print(f"[green]Handle {handle}({hex(handle)}): Read succeeded (data: {data.hex()})[/green]")
                                except BleakError as e:
                                    result["read"] = f"Failed ({e})"
                                    logger.info(f"Handle {handle}({hex(handle)}): Read failed ({e})")
                                    console.print(f"[yellow]Handle {handle}({hex(handle)}): Read failed ({e})[/yellow]")
                                if write_fuzzing:
                                    payload_size = payload_size if not payload_random else random.randint(1, 20)
                                    payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
                                    try:
                                        await client.write_gatt_char(handle, payload, response=True)
                                        result["write"] = f"Succeeded (payload: {payload.hex()})"
                                        logger.info(f"Handle {handle}({hex(handle)}): Write succeeded (payload: {payload.hex()})")
                                        console.print(f"[green]Handle {handle}({hex(handle)}): Write succeeded (payload: {payload.hex()})[/green]")
                                    except BleakError as e:
                                        result["write"] = f"Failed ({e})"
                                        logger.info(f"Handle {handle}({hex(handle)}): Write failed ({e})")
                                        console.print(f"[yellow]Handle {handle}({hex(handle)}): Write failed ({e})[/yellow]")
                                results.append(result)
                                await asyncio.sleep(0.1)
                                current_handle = handle + 1
                                progress.advance(task)
                            retries = 3 #reset counter if device is alive
                        if not device_state["disconnected"]:
                            break
                except BleakError as e:
                    logger.error(f"Connection error at handle {current_handle}: {e}")
                    console.print(f"[red]Connection error at handle {current_handle}: {e}[/red]")
                    if retries > 0:
                        retries -= 1
                        logger.info(f"Retrying connection ({retries} retries left)")
                        console.print(f"[cyan]Retrying connection ({retries} retries left)[/cyan]")
                        await asyncio.sleep(1)
                    else:
                        logger.error("Max retries reached. Stopping fuzzing.")
                        console.print("[red]Max retries reached. Stopping fuzzing.[/red]")
                        break
        else:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Fuzzing handles...", total=len(handle_range))
                for handle in handle_range:
                    try:
                        async with BleakClient(device, timeout=20.0, disconnected_callback=lambda client: on_disconnect(client)) as client:
                            result = {"handle": handle, "read": None, "write": None}
                            try:
                                data = await client.read_gatt_char(handle)
                                result["read"] = f"Succeeded (data: {data.hex()})"
                                logger.info(f"Handle {handle}({hex(handle)}): Read succeeded (data: {data.hex()})")
                                console.print(f"[green]Handle {handle}({hex(handle)}): Read succeeded (data: {data.hex()})[/green]")
                            except BleakError as e:
                                result["read"] = f"Failed ({e})"
                                logger.info(f"Handle {handle}({hex(handle)}): Read failed ({e})")
                                console.print(f"[yellow]Handle {handle}({hex(handle)}): Read failed ({e})[/yellow]")
                            if write_fuzzing:
                                payload_size = payload_size if not payload_random else random.randint(1, 20)
                                payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
                                try:
                                    await client.write_gatt_char(handle, payload, response=True)
                                    result["write"] = f"Succeeded (payload: {payload.hex()})"
                                    logger.info(f"Handle {handle}({hex(handle)}): Write succeeded (payload: {payload.hex()})")
                                    console.print(f"[green]Handle {handle}({hex(handle)}): Write succeeded (payload: {payload.hex()})[/green]")
                                except BleakError as e:
                                    result["write"] = f"Failed ({e})"
                                    logger.info(f"Handle {handle}({hex(handle)}): Write failed ({e})")
                                    console.print(f"[yellow]Handle {handle}({hex(handle)}): Write failed ({e})[/yellow]")
                            results.append(result)
                            await asyncio.sleep(0.1)
                    except BleakError as e:
                        logger.error(f"Connection error for handle {handle}: {e}")
                        console.print(f"[red]Connection error for handle {handle}: {e}[/red]")
                    except Exception as e:
                        logger.error(f"Error for handle {handle}: {e}")
                        console.print(f"[red]Error for handle {handle}: {e}[/red]")
                    progress.advance(task)
    finally:
        if tshark_process:
            try:
                logger.info("Terminating Wireshark capture")
                console.print("[cyan]Terminating Wireshark capture[/cyan]")
                tshark_process.terminate()
                tshark_process.wait(timeout=10)
                logger.info(f"Wireshark capture stopped. Saved to {absolute_pcap}")
                console.print(f"[green]Wireshark capture stopped. Saved to {absolute_pcap}[/green]")
                if os.path.exists(absolute_pcap):
                    logger.info(f"Confirmed PCAP file exists: {absolute_pcap}")
                    console.print(f"[green]Confirmed PCAP file exists: {absolute_pcap}[/green]")
                else:
                    logger.error(f"PCAP file not created: {absolute_pcap}")
                    console.print(f"[red]Error: PCAP file not created: {absolute_pcap}[/red]")
            except Exception as e:
                logger.error(f"Error stopping tshark: {e}")
                console.print(f"[red]Error stopping tshark: {e}[/red]")

    return results

async def fuzz_handles_read_write(device):
    global device_state
    if not device:
        logger.warning("No device selected. Please connect to a device first.")
        console.print("[yellow]No device selected. Please connect to a device first.[/yellow]")
        return

    logger.info(f"Connecting to {device_state['name']} for read/write fuzzing")
    console.print(f"[cyan]Configuring fuzzer for {device_state['name']}[/cyan]")

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
                console.print(f"[green]Maximum handle found: {max_handle}[/green]")
                restrict_range = Confirm.ask(f"Test handle range 1 to {max_handle}?", console=console, default=True)
                if not restrict_range:
                    logger.info("Using full 16-bit range (1 to 65535).")
                    max_handle = 65535
                else:
                    logger.info(f"Using handle range: 1 to {max_handle}")
                    console.print(f"[cyan]Using handle range: 1 to {max_handle}[/cyan]")
            else:
                logger.info("No characteristics or descriptors found.")
                console.print("[yellow]No characteristics or descriptors found.[/yellow]")
    except BleakError as e:
        logger.error(f"Error discovering services: {e}")
        console.print(f"[red]Error discovering services: {e}[/red]")
    except Exception as e:
        logger.error(f"Error: {e}")
        console.print(f"[red]Error: {e}[/red]")

    if max_handle == 0:
        if not Confirm.ask("Could not determine maximum handle. Use full 16-bit range (1 to 65535)?", console=console, default=True):
            handle_range_input = Prompt.ask("Enter handle range (1 to 65535) separated by space (e.g., 1 100)", console=console)
            handle_range_input = list(map(int, handle_range_input.split()))
            if len(handle_range_input) != 2 or handle_range_input[0] < 1 or handle_range_input[1] > 65535 or handle_range_input[0] > handle_range_input[1]:
                logger.error("Invalid handle range. Using full 16-bit range (1 to 65535).")
                console.print("[red]Invalid handle range. Using full 16-bit range (1 to 65535).[/red]")
                min_handle = 1
                max_handle = 65535
            else:
                logger.info(f"Using handle range: {handle_range_input[0]} to {handle_range_input[1]}")
                console.print(f"[cyan]Using handle range: {handle_range_input[0]} to {handle_range_input[1]}[/cyan]")
                min_handle = handle_range_input[0]
                max_handle = handle_range_input[1]
        else:
            max_handle = 65535
    handle_range = range(min_handle, max_handle + 1)

    single_connection = Confirm.ask("Use single connection for all handles? (Faster but more unstable)", console=console, default=False)
    logger.info(f"Using {'single connection' if single_connection else 'per-handle connections'} mode")

    write_fuzzing = Confirm.ask("Enable write fuzzing with random data? (Intrusive)", console=console, default=False)
    logger.info(f"{'Enabling' if write_fuzzing else 'Disabling'} write fuzzing")
    payload_size = 8
    if write_fuzzing:
        payload_size_input = Prompt.ask("Enter payload size for random data (bytes, 0 for random, default 8, max 20)", console=console, default="8")
        payload_size = int(payload_size_input) if payload_size_input.isdigit() else 8
        logger.info(f"Payload size for random data: {payload_size if payload_size > 0 else 'random'}")
        console.print(f"[cyan]Payload size for random data: {payload_size if payload_size > 0 else 'random'}[/cyan]")

    results = await fuzz_handles_read_write_subroutine(device, min_handle, max_handle, handle_range, single_connection, write_fuzzing, payload_size)

    logger.info("Fuzzing complete")
    console.print(Panel("[bold green]Fuzzing complete[/bold green]", style="bold green"))
    readable_handles = [r["handle"] for r in results if r["read"] and r["read"].startswith("Succeeded")]
    writable_handles = [r["handle"] for r in results if r["write"] and r["write"].startswith("Succeeded")]
    if readable_handles or writable_handles:
        if readable_handles:
            logger.info(f"Found {len(readable_handles)} readable handles: {readable_handles}")
            console.print(f"[green]Found {len(readable_handles)} readable handles: {readable_handles}[/green]")
        if writable_handles:
            logger.info(f"Found {len(writable_handles)} writable handles: {writable_handles}")
            console.print(f"[green]Found {len(writable_handles)} writable handles: {writable_handles}[/green]")
    else:
        logger.info("No readable or writable handles found")
        console.print("[yellow]No readable or writable handles found[/yellow]")
    Prompt.ask("Press any key to continue", console=console)

def on_disconnect(client):
    global device_state
    logger.info(f"Connection closed ({client.address})")
    console.print(f"[yellow]Connection closed ({client.address})[/yellow]")
    device_state["disconnected"] = True
    device_state["device"] = None
    device_state["name"] = "none"

def print_menu():
    console.clear()
    table = Table(show_header=False, width=80)
    table.add_column(style="cyan")
    table.add_row("1. Scan for all BLE devices")
    table.add_row("2. Connect to a BLE device")
    table.add_row("3. View all characteristics")
    table.add_row("4. Start fuzzer")
    table.add_row("5. Change logfile")
    table.add_row("6. Exit")
    console.print(table)
    console.print(f"[bold]Current Device:[/bold] {device_state['name']}", style="green")
    console.print(f"[bold]Log File:[/bold] {filename}", style="green")
    console.print(f"[bold]Interface:[/bold] {bt_interface}", style="green")

async def main():
    global device_state
    console.print(Panel(f"[bold magenta]{GMAP_logo}[/bold magenta]", style="bold magenta", width=80))
    #wait two seconds
    time.sleep(2)
    while True:
        print_menu()
        choice = Prompt.ask(f"[bold]Enter your choice [1-6][/bold]", console=console, choices=["1", "2", "3", "4", "5", "6"])
        if choice == "1":
            await discover_devices()
        elif choice == "2":
            dev_name = Prompt.ask("[bold cyan]Insert device name[/bold cyan]", console=console)
            if dev_name:
                device = await find_device(dev_name)
                if not device:
                    console.print("[red]Device not found.[/red]")
            else:
                console.print("[yellow]Please insert a name.[/yellow]")
        elif choice == "3":
            if not device_state["device"]:
                console.print("[yellow]Please select a device first.[/yellow]")
            else:
                console.print(f"[cyan]Getting services for {device_state['name']}...[/cyan]")
                await connect_and_list(device_state["device"])
        elif choice == "4":
            if not device_state["device"]:
                console.print("[yellow]Please select a device first.[/yellow]")
            else:
                console.print(f"[cyan]Starting handle scanner for {device_state['name']}...[/cyan]")
                await fuzz_handles_read_write(device_state["device"])
        elif choice == "5":
            new_filename = Prompt.ask("[bold cyan]Insert new log filename[/bold cyan]", console=console)
            change_log_file(new_filename)
        elif choice == "6":
            console.print("[green]Quitting...[/green]")
            break
        await asyncio.sleep(0.5)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Program terminated by user")
        console.print("\n[green]Quitting...[/green]")
