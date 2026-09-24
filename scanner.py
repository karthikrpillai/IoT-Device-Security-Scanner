import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor



PORTS = {
    21: {
        "service": "FTP",
        "risk": "High",
        "reason": "FTP sends usernames, passwords and files without encryption.",
        "recommendation": "Disable FTP if unnecessary and use a secure alternative such as SFTP.",
    },
    22: {
        "service": "SSH",
        "risk": "Low",
        "reason": "SSH is encrypted, but weak or default passwords can still be guessed.",
        "recommendation": "Use a strong password or key-based login for SSH.",
    },
    23: {
        "service": "Telnet",
        "risk": "High",
        "reason": "Telnet provides remote access without encrypted communication and "
                  "should generally be disabled when not required.",
        "recommendation": "Disable Telnet and use SSH if remote administration is required.",
    },
    80: {
        "service": "HTTP",
        "risk": "Medium",
        "reason": "The web admin page is not encrypted, so login details can be seen on the network.",
        "recommendation": "Use HTTPS for administrative access and change default credentials.",
    },
    443: {
        "service": "HTTPS",
        "risk": "Low",
        "reason": "The web page is encrypted. It is still important to use a strong admin password.",
        "recommendation": "Keep the device firmware updated and use a strong admin password.",
    },
    554: {
        "service": "RTSP",
        "risk": "Medium",
        "reason": "RTSP is used for camera video streams. Many cameras allow viewing without a password.",
        "recommendation": "Enable authentication and restrict camera-stream access.",
    },
    1883: {
        "service": "MQTT",
        "risk": "High",
        "reason": "MQTT on this port is not encrypted. Sensor data and device commands can be read "
                  "or sent by others if authentication is not enabled.",
        "recommendation": "Enable authentication and use MQTT over TLS where supported.",
    },
    2323: {
        "service": "Telnet (alternate)",
        "risk": "High",
        "reason": "Alternate Telnet port. It gives unencrypted remote access and is commonly "
                  "targeted by IoT malware such as Mirai.",
        "recommendation": "Disable Telnet and use SSH if remote administration is required.",
    },
    8080: {
        "service": "HTTP (alternate)",
        "risk": "Medium",
        "reason": "Alternate web admin page without encryption, common on cameras and routers.",
        "recommendation": "Use HTTPS for administrative access and change default credentials.",
    },
    8883: {
        "service": "MQTT over TLS",
        "risk": "Low",
        "reason": "MQTT with encryption. This is the safer way to use MQTT.",
        "recommendation": "Make sure username and password authentication is also enabled.",
    },
}


RISK_LEVELS = ["None", "Low", "Medium", "High", "Critical"]


VENDORS = {
    "18:FE:34": "Espressif",
    "24:0A:C4": "Espressif",
    "24:6F:28": "Espressif",
    "30:AE:A4": "Espressif",
    "5C:CF:7F": "Espressif",
    "84:F3:EB": "Espressif",
    "A4:CF:12": "Espressif",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    "50:C7:BF": "TP-Link",
    "00:17:88": "Philips Hue",
}

IS_WINDOWS = platform.system() == "Windows"




def get_hosts(network_text):
    """Return a list of IP addresses. Only private/local IPv4 networks are allowed."""
    try:
        network = ipaddress.ip_network(network_text.strip(), strict=False)
    except ValueError:
        raise ValueError("Invalid network. Example: 192.168.1.0/24")

    if network.version != 4:
        raise ValueError("Only IPv4 networks are supported.")
    if not (network.is_private or network.is_loopback):
        raise ValueError("Only private/local networks can be scanned (192.168.x.x, 10.x.x.x, 172.16-31.x.x).")
    if network.num_addresses > 256:
        raise ValueError("Network is too big. Please use /24 or smaller.")

    if network.num_addresses == 1:
        return [str(network.network_address)]
    return [str(ip) for ip in network.hosts()]


def get_my_network():
    """Guess this computer's local network, used to fill the input box."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no data is sent, it only finds our local IP
        my_ip = s.getsockname()[0]
    except OSError:
        my_ip = "192.168.1.1"
    finally:
        s.close()
    return str(ipaddress.ip_network(my_ip + "/24", strict=False))



def ping(ip):
    """Return True if the device replies to ping."""
    if IS_WINDOWS:
        command = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        command = ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3,
                                creationflags=0x08000000 if IS_WINDOWS else 0)
        return "ttl=" in result.stdout.lower()
    except (OSError, subprocess.SubprocessError):
        return False


def read_arp_table():
    """Read the ARP table (arp -a) and return a dictionary of IP -> MAC address."""
    try:
        output = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5,
                                creationflags=0x08000000 if IS_WINDOWS else 0).stdout
    except (OSError, subprocess.SubprocessError):
        return {}

    table = {}
    for line in output.splitlines():
        ip = re.search(r"\d+\.\d+\.\d+\.\d+", line)
        mac = re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", line)
        if ip and mac:
            mac_address = ":".join(part.zfill(2) for part in re.split("[:-]", mac.group())).upper()
            if mac_address != "FF:FF:FF:FF:FF:FF":
                table[ip.group()] = mac_address
    return table


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return "Unknown"


def get_vendor(mac):
    if mac == "Unknown":
        return "Unknown"
    return VENDORS.get(mac[:8], "Unknown")




def is_port_open(ip, port):
    """Try a normal TCP connection. If it connects, the port is open."""
    try:
        with socket.create_connection((ip, port), timeout=1):
            return True
    except OSError:
        return False


def get_open_ports(ip):
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = pool.map(lambda port: (port, is_port_open(ip, port)), PORTS)
    return [port for port, is_open in results if is_open]




def guess_device_type(ip, hostname, vendor, open_ports):
    """Guess the device type from vendor, hostname and ports. This is only a guess."""
    name = hostname.lower()

    if vendor == "Espressif" or "esp" in name:
        return "ESP32/ESP8266"
    if vendor == "Raspberry Pi" or "raspberry" in name:
        return "Raspberry Pi"
    if 554 in open_ports or "cam" in name:
        return "IP Camera"
    if "tv" in name or "bravia" in name or "roku" in name:
        return "Smart TV"
    if "printer" in name or "print" in name:
        return "Printer"
    if ip.endswith(".1") or "router" in name or "gateway" in name:
        return "Router"
    if 1883 in open_ports or 8883 in open_ports or 23 in open_ports or 2323 in open_ports:
        return "IoT Device"
    if vendor == "Philips Hue":
        return "IoT Device"
    if "desktop" in name or "laptop" in name or name == "localhost" or 22 in open_ports:
        return "Computer"
    return "Unknown Device"


IOT_TYPES = ["IoT Device", "IP Camera", "Smart TV", "Printer", "Raspberry Pi", "ESP32/ESP8266"]



def get_device_risk(findings):
    """Device risk = highest risk of its open ports.
    If 2 or more High risk services are open, the device is marked Critical."""
    if not findings:
        return "None"
    high_count = sum(1 for f in findings if f["risk"] == "High")
    if high_count >= 2:
        return "Critical"
    return max((f["risk"] for f in findings), key=RISK_LEVELS.index)



def scan_device(ip, mac):
    open_ports = get_open_ports(ip)
    hostname = get_hostname(ip)
    vendor = get_vendor(mac)

    findings = []
    for port in open_ports:
        info = PORTS[port]
        findings.append({
            "port": port,
            "service": info["service"],
            "risk": info["risk"],
            "reason": info["reason"],
            "recommendation": info["recommendation"],
        })

    device_type = guess_device_type(ip, hostname, vendor, open_ports)

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "device_type": device_type,
        "is_iot": device_type in IOT_TYPES,
        "open_ports": open_ports,
        "findings": findings,
        "risk": get_device_risk(findings),
    }



def scan_network(network_text):
    hosts = get_hosts(network_text)

    with ThreadPoolExecutor(max_workers=50) as pool:
        ping_results = pool.map(lambda ip: (ip, ping(ip)), hosts)
    alive = [ip for ip, replied in ping_results if replied]

    arp_table = read_arp_table()
    for ip in arp_table:
        if ip in hosts and ip not in alive:
            alive.append(ip)

   
    if len(hosts) == 1 and not alive:
        alive = hosts

    
    with ThreadPoolExecutor(max_workers=20) as pool:
        devices = list(pool.map(lambda ip: scan_device(ip, arp_table.get(ip, "Unknown")), alive))

    
    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))

    
    findings_count = sum(
        1 for d in devices for f in d["findings"] if f["risk"] in ("Medium", "High")
    )

    return {
        "network": network_text,
        "devices_found": len(devices),
        "iot_devices": sum(1 for d in devices if d["is_iot"]),
        "security_findings": findings_count,
        "devices": devices,
    }
