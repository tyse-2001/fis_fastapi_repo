from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from .form import DomainIpForm, FilesForm

import json

import requests

# Create your views here.

def index(request):
    return render(request, 'fastapi_table/index.html')

# Domain_Ip functions
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

    if not "detail" in file_dict:
        ref_files = file_dict["ref_files"]
        comm_files = file_dict["comm_files"]

        file_dict.pop("ref_files")
        file_dict.pop("comm_files")
    else:
        file_dict = {}
        ref_files = []
        comm_files = []

    context = {
        'json': file_dict,
        'ref_files': ref_files,
        'comm_files': comm_files,
        'form': DomainIpForm()
    }

    return render(request, 'fastapi_table/domain_ip_page.html', context)

# Files functions
def files_search(request):
    return render(request, 'fastapi_table/files_search.html')

def files_redirect(request):
    if request.method == 'GET':
        form = FilesForm(request.GET)
        if form.is_valid():
            return HttpResponseRedirect(
                '/fastapi_table/files/' + str(form.cleaned_data['file_name'])
            )
    else:
        form = FilesForm()

    return render(request, 'fastapi_table/name.html', {'form': form})

def search_files(request, file_id):
    url = "http://127.0.0.1:8000/scan/files/" + file_id
    file_dict = json.loads(requests.get(url).text)

    if not "detail" in file_dict:
        exec_parent = file_dict["exec_parent"]
        file_dict.pop("exec_parent")
    else:
        file_dict = {}
        exec_parent = []

    context = {
        'json': file_dict,
        'exec_parent': exec_parent,
        'form': FilesForm()
    }

    return render(request, 'fastapi_table/files_page.html', context)