import socket
from concurrent.futures import ThreadPoolExecutor

def check_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        if s.connect_ex((host, port)) == 0:
            return port
    return None

target = "8.8.8.8"
ports = range(1, 1025)

print(f"Сканирование {target}...")
with ThreadPoolExecutor(max_workers=100) as executor:
    results = executor.map(lambda p: check_port(target, p), ports)

for res in results:
    if res:
        print(f"Порт {res} открыт")

