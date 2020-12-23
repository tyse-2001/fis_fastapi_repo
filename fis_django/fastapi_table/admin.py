from django.contrib import admin

from .models import Files, DomainIp

# Register your models here.

admin.site.register(Files)
admin.site.register(DomainIp)
