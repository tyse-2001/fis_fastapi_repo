from django.shortcuts import render
from django.http import HttpResponse

import requests

# Create your views here.

def index(request):
    url = "http://127.0.0.1:8000/scan/domain_ip/google.com"
    return HttpResponse(requests.get(url).text)