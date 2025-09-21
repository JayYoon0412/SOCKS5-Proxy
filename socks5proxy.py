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
        # IPv4 and TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen()
        try:
            while True:
                client_socket, client_addr = sock.accept()
                client_ip = client_addr[0]
                if(is_blocked(client_socket, client_ip)):
                    continue
                threading.Thread(target=self.proxy, args=(client_socket,), daemon=True).start()
        except KeyboardInterrupt:
            print("Shutting down...")
        finally:
            try: sock.close()
            except: pass

    def proxy(self, client_socket: socket.socket):
        try:
            # STEP 1: VER, AUTHENTICATION METHODS
            ver, nmethods = read_bytes(client_socket, 2)
            # only version 5 should be supported
            if ver != 0x05:
                client_socket.close()
                raise ConnectionError("version not supported.")
            methods = read_bytes(client_socket, nmethods)
            # only need to support "no authentication"
            if 0x00 not in methods:
                raise ConnectionError("authentication method not supported.")
            client_socket.sendall(b"\x05\x00")

            # STEP 2: CONNECT REQUEST
            ver, cmd, _, atyp = read_bytes(client_socket, 4)
            # cmd limited to connect x'01'
            if ver != 0x05 or cmd != 0x01:
                client_socket.sendall(self.construct_req_reply(0x05))
                client_socket.close()
                return
            # address type: IPV4
            if atyp == 0x01:
                dst_addr_bytes = read_bytes(client_socket, 4)
                dst_addr = socket.inet_ntoa(dst_addr_bytes)
            # address type: domain name
            elif atyp == 0x03:
                len, = read_bytes(client_socket, 1)
                dst_addr_bytes = read_bytes(client_socket, len)
                dst_addr = dst_addr_bytes.decode("ascii")
            else:
                client_socket.sendall(self.construct_req_reply(0x05))
                return

            dst_port_bytes = read_bytes(client_socket, 2)
            dst_port = int.from_bytes(dst_port_bytes,"big")

            # STEP 3: REMOTE CONNECT
            remote_socket = None
            try:
                remote_socket = socket.create_connection((dst_addr, dst_port))
            except Exception:
                client_socket.sendall(self.construct_req_reply(0x05))
                return
            
            # STEP 4: CONNECT REPLY
            bnd_addr, bnd_port = remote_socket.getsockname()
            client_socket.sendall(self.construct_req_reply(0x00, bnd_addr, bnd_port))

            # STEP 5: RELAY PROCESSING
            self.relay(client_socket, remote_socket)
            
        except Exception:
            pass
        finally:
            try: client_socket.close()
            except: pass
            if remote_socket:
                try: remote_socket.close()
                except: pass

    def construct_req_reply(self, rep: int, bnd_addr: str = "0.0.0.0", bnd_port: int = 0):
        ver = b"\x05"
        rsv = b"\x00"
        atyp = b"\x01"
        bnd_addr_bytes = socket.inet_aton(bnd_addr)
        bnd_port_bytes = bnd_port.to_bytes(2,"big")
        pkt = ver+rep.to_bytes(1,"big")+rsv+atyp+bnd_addr_bytes+bnd_port_bytes
        return pkt
    
    def relay(self, client_socket, remote_socket):
        while True:
            readable, _, _ = select.select([client_socket, remote_socket], [], [])
            for sock in readable:
                data = sock.recv(4096)
                if data:
                    if sock is client_socket:
                        remote_socket.sendall(data)
                        print(f"Client -> Remote {len(data)} bytes")
                    else:
                        client_socket.sendall(data)
                        print(f"Remote -> Client {len(data)} bytes")
                
if __name__ == "__main__":
    Socks5Proxy().start()
