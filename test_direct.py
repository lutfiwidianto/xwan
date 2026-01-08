# test_direct.py - Test direct ke SSH server dengan header manipulation
import socket
import ssl

def test_direct_ssh(ssh_host, ssh_port, whitelist_domain):
    """Test direct connection dengan header manipulation"""
    
    # Payload dengan Host header iflix.com
    payloads = [
        f"CONNECT {ssh_host}:{ssh_port} HTTP/1.1\r\nHost: {whitelist_domain}\r\n\r\n",
        f"GET / HTTP/1.1\r\nHost: {whitelist_domain}\r\nX-Online-Host: {whitelist_domain}\r\n\r\n",
    ]
    
    for i, payload in enumerate(payloads):
        print(f"\n[*] Testing payload {i+1}...")
        
        # Coba direct ke berbagai port
        for port in [80, 443, 8080]:
            try:
                if port == 443:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(
                        socket.create_connection((ssh_host, port), timeout=10),
                        server_hostname=whitelist_domain
                    )
                else:
                    sock = socket.create_connection((ssh_host, port), timeout=10)
                
                sock.sendall(payload.encode())
                response = sock.recv(4096)
                
                print(f"  Port {port}: {response[:100]}...")
                
                if b"SSH-2.0" in response or b"HTTP/" in response:
                    print(f"  [SUCCESS] Response received!")
                    return True
                    
                sock.close()
            except Exception as e:
                print(f"  Port {port}: {e}")
    
    return False

# Test direct
test_direct_ssh("d3n5jwfln9l01g.cloudfront.net", 80, "www.iflix.com")