import requests

url = "http://127.0.0.1:8000/scan/domain_ip/google.com"
x = requests.get(url).text
print(x)