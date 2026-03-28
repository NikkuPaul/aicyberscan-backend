import httpx
import socket

FREE_PORT_DB = {
    21: "FTP — often vulnerable to anonymous login",
    22: "SSH — check for weak credentials",
    23: "Telnet — insecure protocol",
    25: "SMTP — email spoofing risk",
    53: "DNS — open resolver risk",
    80: "HTTP — check for outdated server",
    110: "POP3 — insecure protocol",
    143: "IMAP — insecure protocol",
    443: "HTTPS — check TLS",
    3306: "MySQL — check for open DB",
    3389: "RDP — brute force risk",
    8080: "Proxy/Web server — check headers"
}

async def scan_ports(domain: str):
    try:
        ip = socket.gethostbyname(domain)
    except:
        return {"error": "Could not resolve domain"}

    open_ports = []

    for port in FREE_PORT_DB.keys():
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append({"port": port, "description": FREE_PORT_DB[port]})
            sock.close()
        except:
            pass

    return open_ports
