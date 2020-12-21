from django.shortcuts import render

def index(request):
    return render(request, 'fis_django/index.html')