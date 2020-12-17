from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from .form import DomainIpForm

import json

import requests

# Create your views here.

def index(request):
    return HttpResponse("url")

def domain_ip_search(request):
    return render(request, 'fastapi_table/domain_ip_search.html')

def domain_ip_redirect(request):
    if request.method == 'GET':
        form = DomainIpForm(request.GET)
        if form.is_valid():
            return HttpResponseRedirect(
                '/fastapi_table/domain_ip/' + str(form.cleaned_data['domain_ip_name'])
            )
    else:
        form = DomainIpForm()

    return render(request, 'fastapi_table/name.html', {'form': form})

def search_domain_ip(request, object_id):
    url = "http://127.0.0.1:8000/scan/domain_ip/" + object_id
    file_dict = json.loads(requests.get(url).text)

    ref_files = file_dict["ref_files"]
    comm_files = file_dict["comm_files"]
    
    file_dict.pop("ref_files")
    file_dict.pop("comm_files")

    context = {
        'json': file_dict,
        'ref_files': ref_files,
        'comm_files': comm_files
    }

    return render(request, 'fastapi_table/index.html', context)
    