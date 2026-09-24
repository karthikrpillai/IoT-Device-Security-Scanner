# IoT Device Security Scanner

Name: Karthik R Pillai
Roll NO: 2405101010127
Class: BCA Regular 5th Semester
Div: D
Subject: Cyber Security in Mobile, Cloud and IoT

# Introduction

Most homes today have many IoT devices connected to the Wi-Fi like routers, IP cameras,
smart TVs and smart plugs. Many of these devices have insecure services running such as
Telnet or MQTT without encryption, which attackers can use to get access to the device.

This project scans a local network, finds the connected devices, checks some common
IoT ports and shows the risk level of each device along with a simple recommendation.
The results are shown on a web page made using Flask.

# Features

- Scan local network (example: 127.0.0.1)
- Find devices connected to the network
- Show IP address, MAC address, hostname and vendor
- Check open ports
- Identify the service running on each port
- Show the risk level
- Give security recommendations
- Simple web dashboard

# Technologies Used

- Python 3
- Flask
- HTML, CSS, JavaScript

# Project Files

iotdevicescanner/
 app.py
 scanner.py
 fake_device.py
 requirements.txt
README.txt
 static/
    index.html
    style.css
    script.js

File | Use 

| app.py - Flask server, runs the web page and the scan 
| scanner.py - Finds devices, checks ports and gives risk level 
| fake_device.py - Fake IoT device used for testing 
| index.html - Dashboard page 
| style.css - Design of the page 
| script.js - Sends scan request and shows the results 

# How to Install

1. Install Python 3 

2. Open command prompt in the project folder and run

pip install -r requirements.txt


# How to Run

python app.py

Open the browser and go to local host

Enter the network range and click SCAN NETWORK. Click on any device to see the details.

# Testing

A fake IoT device is included for testing. It runs only on the same computer.

Open another command prompt in the project folder and run


python fake_device.py

Then enter IP address in the scanner and click SCAN NETWORK.
Click on the Device List to see the Device Details.

Result:

| Port | Service | Risk |
| 554 | RTSP | Medium |
| 1883 | MQTT | High |
| 2323 | Telnet | High |
| 8080 | HTTP | Medium |

# Ports Checked

| Port | Service | Risk |
| 21 | FTP | High |
| 22 | SSH | Low |
| 23 | Telnet | High |
| 80 | HTTP | Medium |
| 443 | HTTPS | Low |
| 554 | RTSP | Medium |
| 1883 | MQTT | High |
| 2323 | Telnet | High |
| 8080 | HTTP | Medium |
| 8883 | MQTT over TLS | Low |

# Risk Levels

- Critical - two or more high risk services open on the same device
- High - Telnet, FTP or MQTT without encryption
- Medium - HTTP admin page or RTSP camera stream
- Low - encrypted services like SSH, HTTPS, MQTT over TLS
- None - no risky ports found

# Working

1. The user enters the network range on the web page.
2. The program checks that it is a private network. Public IP ranges are not allowed.
3. Every IP address in the range is pinged and the ARP table is read to find the
   devices and their MAC addresses.
4. For each device, a TCP connection is tried on each port in the list. If it
   connects, the port is open.
5. Each open port is matched with its service, risk level and recommendation.
6. The device type is guessed using the vendor, hostname and open ports.
7. The results are sent back to the web page and shown in the table.


# Limitations

- Only the ports in the list are checked
- Device type is only a guess and may not always be correct
- Some phones use random MAC addresses so the vendor cannot be found

# Future Scope

- Check more ports and services
- Show an alert when a new device joins the network
- Save scan reports

# Conclusion

This project shows that IoT devices on a home network can have insecure services
like Telnet and unencrypted MQTT open. By turning off unused services, changing
default passwords and using secure protocols like SSH, HTTPS and MQTT over TLS,
the security of these devices can be improved.

Note: Only scan networks you own or have permission to test.