# test_proxy.py
import socket

def test_proxy(proxy_host, proxy_port):
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=5)
        print(f"[OK] {proxy_host}:{proxy_port} - Bisa connect")
        
        # Coba kirim request sederhana
        request = f"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
        sock.sendall(request.encode())
        response = sock.recv(1024)
        
        if b"HTTP/" in response:
            print(f"     Response: {response[:100]}...")
        else:
            print(f"     No HTTP response")
        
        sock.close()
        return True
    except Exception as e:
        print(f"[FAIL] {proxy_host}:{proxy_port} - {e}")
        return False

# Test beberapa kemungkinan proxy
test_list = [
    ("192.168.1.1", 80),
    ("8.8.8.8", 80),
    ("1.1.1.1", 80),
    ("www.iflix.com", 80),  # Ini bukan proxy!
]

for host, port in test_list:
    test_proxy(host, port)