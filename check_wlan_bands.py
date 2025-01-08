import subprocess
import sys
import shutil

def check_dependency(command, install_command):
    """
    Check if a dependency exists, and if not, attempt to install it.
    """
    if shutil.which(command) is None:
        print(f"Dependency '{command}' is missing. Attempting to install...")
        try:
            subprocess.run(install_command, shell=True, check=True)
            print(f"Successfully installed '{command}'.")
        except subprocess.CalledProcessError:
            print(f"Failed to install '{command}'. Please install it manually.")
            sys.exit(1)

def check_and_install_prerequisites():
    """
    Ensure that all required dependencies are installed.
    """
    print("Checking and installing prerequisites...")
    # Check for 'iw' tool
    check_dependency('iw', 'sudo apt update && sudo apt install -y iw')

def get_wireless_bands():
    """
    Determine supported wireless bands using 'iw list'.
    """
    try:
        # Run the 'iw list' command
        result = subprocess.run(['iw', 'list'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(f"Error: {result.stderr.strip()}")
            return None
        
        output = result.stdout

        # Parse the output for frequency bands
        bands = []
        if "Frequencies:" in output:
            if any(freq in output for freq in ["2412.0 MHz", "2417.0 MHz", "2422.0 MHz"]):
                bands.append("2.4 GHz")
            if any(freq in output for freq in ["5180.0 MHz", "5200.0 MHz", "5240.0 MHz"]):
                bands.append("5 GHz")
        
        return bands
    except FileNotFoundError:
        print("Error: 'iw' command not found. Please install the 'iw' tool.")
        return None

def main():
    # Ensure prerequisites are met
    check_and_install_prerequisites()

    print("Checking supported frequency bands...")
    bands = get_wireless_bands()
    if bands:
        print(f"Supported frequency bands: {', '.join(bands)}")
    else:
        print("Unable to determine supported frequency bands. Ensure the wireless adapter and 'iw' tool are working properly.")

if __name__ == "__main__":
    main()
