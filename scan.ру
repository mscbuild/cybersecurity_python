import requests
import json

NESSUS_URL = "https://your-nessus-server:8834"
USERNAME = "your_username"
PASSWORD = "your_password"

# Авторизация в Nessus
def authenticate():
    data = {
        "username": USERNAME,
        "password": PASSWORD
    }
    response = requests.post(f"{NESSUS_URL}/session", data=data, verify=False)
    if response.status_code == 200:
        token = response.json()['token']
        print(f"Успешная авторизация. Токен: {token}")
        return token
    else:
        print("Ошибка авторизации")
        return None

# Получение информации о сканировании
def get_scan_results(token, scan_id):
    headers = {
        "X-Cookie": f"token={token}"
    }
    response = requests.get(f"{NESSUS_URL}/scans/{scan_id}", headers=headers, verify=False)
    if response.status_code == 200:
        results = response.json()
        print(f"Результаты сканирования: {json.dumps(results, indent=4)}")
    else:
        print("Ошибка при получении результатов")

# Пример использования
if __name__ == "__main__":
    token = authenticate()
    if token:
        scan_id = "your_scan_id"
        get_scan_results(token, scan_id)

