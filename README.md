# banner-scanner

is a powerful, multi-protocol banner grabbing and port scanning tool designed for security assessments and penetration testing. It effectively detects services running on target ports and extracts banners, including those requiring special interaction (e.g., pressing Enter multiple times).

## Features

Full & Custom Port Scanning: Scan all 65535 ports or specify a range.
Top Dangerous Ports: Scan 500+ high-risk ports commonly exploited.
Advanced Banner Grabbing: Works on services requiring interaction, including:

FTP (Port 21): Attempts USER anonymous login.
MySQL (Port 3306): Sends \x03SELECT VERSION(); to retrieve version.
Adaptive Rate Limiting: Avoids triggering firewalls/IPS/IDS.
Randomized Timing: Evades security mechanisms by delaying requests.
Handles HTTP & HTTPS URLs: Automatically extracts domain and removes protocols.

## Installation

Ensure you have Go installed. Then, clone the repository and build the binary:

`go install github.com/Vulnpire/banner-scanner@latest`

## Usage

### Scan a target for all ports (1-65535)

`cat targets.txt | ./banner-scanner -pr 1-65535`

### Scan only top 500 dangerous ports

`cat targets.txt | ./banner-scanner -top-ports`

### Scan a specific port range (e.g., 20-1000)

`cat targets.txt | ./banner-scanner -pr 20-1000`

### Adjust rate limit (to evade firewalls)

`cat targets.txt | ./banner-scanner -r 50`

Example Output

    sub.example.com:21 - 220 Microsoft FTP Service
    sub.example.com:20880 - dubbo>
    192.168.1.10:3306 - MySQL 8.0.31

### Future Plans

🔹 More protocol-specific fingerprinting (e.g., Redis, Telnet, SNMP)

🔹 Parallel DNS resolution for mass scanning

🔹 Output in JSON & CSV formats for automation

### Axiom Support

```
» cat ~/.axiom/modules/banner-scanner.json
[{
        "command":"cat input | banner-scanner -top-ports | anew output",
        "ext":"txt"
}]
```

🚀 Stay stealthy & ethical!
