# ICMP Sniffing Tool (x64 Assembly)

A high-performance, low-level ICMP packet sniffer written entirely in x84_64 Assembly. This tool utilizes Linux raw sockets to intercept ICMP traffic, manually parses IP/ICMP headers, and extracts payloads directly from the kernel interface.
🚀 Features
Zero Dependencies: Written in pure Assembly, no C standard library (libc) required.

Raw Socket Integration: Uses sys_socket (syscall 41) for direct network interface access.

Manual Protocol Parsing: Implements custom logic to strip 20-byte IPv4 and 8-byte ICMP headers.

Custom Integer-to-ASCII Engine: A hand-optimized algorithm to convert binary IP addresses into human-readable dotted-decimal format.

Lightweight: Minimal memory footprint and high execution speed.

🛠️ Technical Overview
The core of the application revolves around the sys_recvfrom (syscall 45) which captures incoming packets into a 1200-byte buffer. The tool then calculates the offset to skip the headers and reach the data:

IPv4 Header: 20 Bytes

ICMP Header: 8 Bytes

Payload Start: Buffer + 28 Bytes

📋 Prerequisites
NASM: The Netwide Assembler.

Binutils: For the ld linker.

Linux Environment: Designed specifically for the Linux x86_64 kernel.

Root Privileges: Required for opening raw sockets.

### 🔨 Build and Run

1. **Assemble the source code:**
```bash
nasm -f elf64 icmp_sniff.asm -o icmp_sniff.o
```
2. Link the object file:
```bash
ld icmp_sniff.o -o icmp_sniff
```
3. Run with root privileges:
```bash
sudo ./icmp_sniff
```
⚠️ Disclaimer
This project is developed for educational and ethical security research purposes only. The author is not responsible for any misuse of this tool. Unauthorized sniffing of network traffic may be illegal in your jurisdiction.
