
import subprocess
import re
from scapy.all import ARP, sniff, srp, Ether
import os

def get_wifi_info():
    wifi_info = {}
    
    # Get SSID and other details using nmcli
    try:
        result = subprocess.run(['nmcli', '-t', '-f', 'ACTIVE,SSID,BSSID,CHAN,RATE,SIGNAL,BARS,SECURITY', 'device', 'wifi'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            print(f"Error: {result.stderr.decode()}")
            return wifi_info
        
        output = result.stdout.decode()
        for line in output.splitlines():
            if line.startswith("yes"):
                parts = line.split(':')
                wifi_info = {
                    'SSID': parts[1],
                    'BSSID': parts[2],
                    'Channel': parts[3],
                    'Rate': parts[4],
                    'Signal Strength': parts[5],
                    'Signal Bars': parts[6],
                    'Security': parts[7]
                }
                break
    except Exception as e:
        print(f"Exception occurred: {e}")
    
    return wifi_info

def check_vulnerabilities(wifi_info):
    vulnerabilities = []
    
    if not wifi_info:
        return vulnerabilities
    
    # Check for open networks
    if 'WPA' not in wifi_info['Security'] and 'WEP' not in wifi_info['Security']:
        vulnerabilities.append("The network is open and unencrypted. This makes it susceptible to eavesdropping and MITM attacks.")
    
    # Check for WEP encryption
    if 'WEP' in wifi_info['Security']:
        vulnerabilities.append("The network uses WEP encryption, which is outdated and easily crackable.")
    
    # Check for weak signal
    signal_strength = int(wifi_info['Signal Strength'].replace('%', ''))
    if signal_strength < 50:
        vulnerabilities.append("The signal strength is weak, which can make the network more susceptible to certain types of attacks like deauthentication attacks.")

    return vulnerabilities

def get_connected_devices():
    devices = []
    try:
        arp_request = ARP(pdst="192.168.1.1/24")
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        for sent, received in answered_list:
            devices.append({'IP': received.psrc, 'MAC': received.hwsrc})
    except Exception as e:
        print(f"Exception occurred while fetching connected devices: {e}")
    
    return devices

def main():
    wifi_info = get_wifi_info()
    if not wifi_info:
        print("Failed to retrieve WiFi information.")
        return
    
    print("WiFi Information:")
    for key, value in wifi_info.items():
        print(f"{key}: {value}")
    
    vulnerabilities = check_vulnerabilities(wifi_info)
    print("\nPotential Vulnerabilities:")
    for vulnerability in vulnerabilities:
        print(f"- {vulnerability}")
    
    connected_devices = get_connected_devices()
    print("\nConnected Devices:")
    for device in connected_devices:
        print(f"IP: {device['IP']}, MAC: {device['MAC']}")

if __name__ == "__main__":
    main()
