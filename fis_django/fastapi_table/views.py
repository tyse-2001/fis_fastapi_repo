import json

import requests
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.template import loader

from .form import DomainIpForm, FilesForm
from .models import DomainIp, ReferrerFiles, CommunicatingFiles, Files, ExecutionParents

# Create your views here.

def index(request):
    return render(request, 'fastapi_table/index.html')

def search_page(request):
    context = {
        'domain_ip_form': DomainIpForm(),
        'files_form': FilesForm(),
    }
    return render(request, 'fastapi_table/search.html', context)

# Domain_Ip functions
def domain_ip_search(request):
    context = {
        'domain_ip_form': DomainIpForm(),
        'files_form': FilesForm(),
        'domain_ip_list': DomainIp.objects.all()
    }
    return render(request, 'fastapi_table/domain_ip_search.html', context)

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
        check = 0
        try:
            check = DomainIp.objects.get(object_id=object_id)
            #print(obj.object_id)
        except Exception as e:
            print(e)

        if not check:
            entry = DomainIp.objects.create_domain_ip(
                file_dict["object_id"],
                file_dict["object_type"],
                file_dict["object_last_updated"],
                file_dict["score"],
                file_dict["severity"],
                file_dict["comm_count"],
                file_dict["ref_count"],
            )


        ref_files = file_dict["ref_files"]
        check = 0
        try:
            check = ReferrerFiles.objects.all().filter(related_object_id=object_id)
        except Exception as e:
            print(e)
        if not check:
            for dictionary in ref_files:
                referrer_file_entry = ReferrerFiles.objects.create_referrer_file(
                    dictionary["ref_file_id"],
                    dictionary["ref_file_name"],
                    dictionary["related_object_id"],
                    dictionary["date_scanned"],
                    dictionary["detection_score"],
                    dictionary["severity"],
                    dictionary["ref_file_type"]
                )
        check = 0
        comm_files = file_dict["comm_files"]
        try:
            check = CommunicatingFiles.objects.all().filter(related_object_id=object_id)
        except Exception as e:
            print(e)
        if not check:
            for dictionary in comm_files:
                communicating_file_entry = CommunicatingFiles.objects.create_communicating_file(
                    dictionary["comm_file_id"],
                    dictionary["comm_file_name"],
                    dictionary["related_object_id"],
                    dictionary["date_scanned"],
                    dictionary["detection_score"],
                    dictionary["severity"],
                    dictionary["comm_file_type"]
                )

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
        'domain_ip_form': DomainIpForm(),
        'files_form': FilesForm(),
    }

    return render(request, 'fastapi_table/domain_ip_page.html', context)

# Files functions
def files_search(request):
    context = {
        'domain_ip_form': DomainIpForm(),
        'files_form': FilesForm(),
        'files_list': Files.objects.all()
    }
    return render(request, 'fastapi_table/files_search.html', context)

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
        check = 0
        try:
            check = Files.objects.get(file_id=file_id)
        except Exception as e:
            print(e)
        
        if not check:
            entry = Files.objects.create_file(
                file_dict["file_id"],
                file_dict["file_name"],
                file_dict["file_date_scanned"],
                file_dict["score"],
                file_dict["severity"],
                file_dict["exec_parent_count"],
            )

        check = 0
        try:
            check = ExecutionParents.objects.all().filter(related_file_id=file_id)
        except Exception as e:
            print(e)
        
        exec_parent = file_dict["exec_parent"]
        if not check:
            for dictionary in exec_parent:
                exec_parent_entry = ExecutionParents.objects.create_exec_parent(
                    dictionary["parent_id"],
                    dictionary["related_file_id"],
                    dictionary["exec_date_scanned"],
                    dictionary["detection_score"],
                    dictionary["severity"],
                    dictionary["parent_type"],
                )

        file_dict.pop("exec_parent")
    else:
        file_dict = {}
        exec_parent = []

    context = {
        'json': file_dict,
        'exec_parent': exec_parent,
        'domain_ip_form': DomainIpForm(),
        'files_form': FilesForm(),
    }

    return render(request, 'fastapi_table/files_page.html', context)
