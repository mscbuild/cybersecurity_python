import scapy.all as scapy
import time

# Список подозрительных IP и портов для простого обнаружения
suspicious_ips = []
suspicious_ports = [21, 23, 445]  # Примеры портов, которые могут быть использованы для атак (FTP, Telnet, SMB)
suspect_threshold = 10  # Порог для слишком частых запросов с одного IP

# Хранилище IP-адресов для отслеживания запросов
ip_request_count = {}

# Функция для анализа пакетов
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        packet_protocol = packet[scapy.IP].proto
        
        # Логирование подозрительных IP
        if ip_src not in ip_request_count:
            ip_request_count[ip_src] = 1
        else:
            ip_request_count[ip_src] += 1

        # Проверка на подозрительные порты
        if packet.haslayer(scapy.TCP):
            dst_port = packet[scapy.TCP].dport
            src_port = packet[scapy.TCP].sport
            
            if dst_port in suspicious_ports or src_port in suspicious_ports:
                print(f"Подозрительный порт {dst_port} или {src_port} в пакете от {ip_src} до {ip_dst}")

        # Проверка на частые запросы с одного IP (для предотвращения DDoS атак)
        if ip_request_count[ip_src] > suspect_threshold:
            if ip_src not in suspicious_ips:
                suspicious_ips.append(ip_src)
                print(f"Подозрительная активность от IP {ip_src} (слишком много запросов)")

        # Выводим информацию о каждом пакете
        print(f"Пакет от {ip_src} к {ip_dst}, Протокол: {packet_protocol}")

# Запуск захвата пакетов
def start_sniffing():
    print("Запуск мониторинга сети...")
    scapy.sniff(prn=packet_callback, store=0)

# Запуск функции захвата
if __name__ == "__main__":
    start_sniffing()

