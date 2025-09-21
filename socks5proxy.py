import socket
import select
import threading
import ipaddress

allowed_ranges = [
    ipaddress.ip_network("67.159.64.0/18"),
    ipaddress.ip_network("152.3.0.0/16"),
    ipaddress.ip_network("152.16.0.0/16"),
    ipaddress.ip_network("152.22.224.0/20"),
    ipaddress.ip_network("10.0.0.0/8")
]

def is_blocked(client_socket : socket.socket, ip : str) -> bool:
    """If an IP should be blocked, closes the socket and returns True."""
    ip_obj = ipaddress.ip_address(ip)

    if ip_obj.is_loopback:
        return False

    if not any(ip_obj in allowed_range for allowed_range in allowed_ranges):
        client_socket.close()
        return True
    
    return False

def read_bytes(client_socket : socket.socket, n : int) -> bytes:
    """Reads exactly n bytes from stream and returns bytes"""
    buffer = bytearray()
    while(len(buffer) < n):
        byte = client_socket.recv(n-len(buffer))
        if not byte:
            raise ConnectionError()
        buffer += byte
    return bytes(buffer)

class Socks5Proxy:
    def __init__(self, host="0.0.0.0", port=1080):
        self.host = host
        self.port = port

    def start(self):
        """use IPv4 and TCP for socket"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen()
        print(f"SOCKS5 listening on {self.host}:{self.port}")
        try:
            while True:
                client_socket, client_addr = sock.accept()
                client_ip = client_addr[0]
                if(is_blocked(client_socket, client_ip)):
                    continue
                threading.Thread(target=self.proxy, args=(client_socket, client_addr), daemon=True).start()
        finally:
            sock.close

    def proxy(self, client_socket: socket.socket, addr):
        print("Hello World!")

if __name__ == "__main__":
    Socks5Proxy().start()
