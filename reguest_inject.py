import requests

# Send a GET request to a web server
response = requests.get('https://www.google.com')

# Check the response status code
if response.status_code == 200:
    print('Request successful')
else:
    print('Request failed')

# Print the response headers and content
print('Headers:', response.headers)
print('Content:', response.text)
