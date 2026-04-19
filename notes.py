# Lecture Notes - Networks and Systems
# University of Nairobi - CS Department
# Week 7 - Subnetting & Socket Programming

import socket
import struct

# ----------------------------
# SUBNETTING CALCULATIONS
# ----------------------------

def calculate_subnet(ip, cidr):
    mask = (0xFFFFFFFF >> (32 - cidr)) << (32 - cidr)
    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    network = ip_int & mask
    broadcast = network | (~mask & 0xFFFFFFFF)
    hosts = broadcast - network - 1

    print(f"IP Address     : {ip}/{cidr}")
    print(f"Subnet Mask    : {socket.inet_ntoa(struct.pack('!I', mask))}")
    print(f"Network Address: {socket.inet_ntoa(struct.pack('!I', network))}")
    print(f"Broadcast      : {socket.inet_ntoa(struct.pack('!I', broadcast))}")
    print(f"Usable Hosts   : {hosts}")
    print("-" * 40)

# Test cases from lecture
calculate_subnet("192.168.1.0", 24)
calculate_subnet("10.0.0.0", 8)
calculate_subnet("172.16.0.0", 16)


# ----------------------------
# BASIC TCP SOCKET EXAMPLE
# ----------------------------

def tcp_client_example():
    host = "127.0.0.1"
    port = 8080

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response = s.recv(1024)
        print("Response received:")
        print(response.decode())
        s.close()
    except (socket.timeout, ConnectionRefusedError):
        print(f"[INFO] No server running on {host}:{port} — expected in test environment")

tcp_client_example()


# ----------------------------
# OSI LAYER REFERENCE
# ----------------------------

osi_layers = {
    1: ("Physical",     "Cables, switches, electrical signals"),
    2: ("Data Link",    "MAC addresses, Ethernet frames, error detection"),
    3: ("Network",      "IP addressing, routing, packet forwarding"),
    4: ("Transport",    "TCP/UDP, ports, flow control, segmentation"),
    5: ("Session",      "Session management, authentication, reconnection"),
    6: ("Presentation", "Encryption, compression, data formatting"),
    7: ("Application",  "HTTP, FTP, DNS, SMTP — user-facing protocols"),
}

print("OSI Model Reference:")
print("-" * 55)
for layer_num, (name, description) in osi_layers.items():
    print(f"Layer {layer_num} - {name:<15}: {description}")

print("\nNotes: TCP operates at Layer 4. IP operates at Layer 3.")
print("Most application vulnerabilities occur at Layer 7.")
