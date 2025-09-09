# GMAP: BLE Advertisement Analyzer and Bluetooth GATT Mapper
```bash
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
```


GMAP is a tool for analyzing BLE advertisements and mapping Bluetooth GATT characteristics. It features a graphical user interface for ease of use.

## Features
- Scan for BLE devices
- Connect to a BLE device
- View GATT services and characteristics
- Fuzz BLE characteristics
- Log actions and errors

## Installation

### Prerequisites
- Python 3.8+
- Linux (recommended)
- Bluetooth adapter

### Install dependencies
```bash
# Clone the repository (if not already)
git clone <your-repo-url>
cd GMAP_project

# Install Python dependencies
pip install bleak rich
```

## Virtual environment
Create python venv:
```bash
python3 -m venv venv
```

## Usage
Run the main GUI:
```bash
sudo venv/bin/python3.10 main_gui.py
```

## Menu Description
When you start the tool, you'll see a menu with the following options:

1. **Scan for all BLE devices**
   - Scans for nearby BLE devices and displays their names, addresses, and advertisement data.
2. **Connect to a BLE device**
   - Prompts for a device name and attempts to connect.
3. **View all characteristics**
   - Lists all GATT services, characteristics, and descriptors for the connected device.
4. **Start fuzzer**
   - Fuzzes handles with read/write operations. You can choose the handle range, connection mode, and payload size.
5. **Change logfile**
   - Change the log file used for output.
6. **Exit**
   - Quit the program.

## Logging
- All actions and errors are logged to `ble_fuzzer.log` by default.
- You can change the log file from the menu.

## Notes
- Make sure your Bluetooth adapter is enabled and accessible.
- You may need root privileges for BLE operations.
- Fuzzing with write operations can be intrusive and may affect device stability.

## Troubleshooting
- If you encounter permission errors, try running with `sudo`.
- For BLE errors, check device compatibility and proximity.

## Author
- Firrera, Manuel(ESEC/3)
