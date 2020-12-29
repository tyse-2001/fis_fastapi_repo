from django.contrib import admin

from .models import DomainIp, Files

# Register your models here.

@admin.register(Files)
class FilesAdmin(admin.ModelAdmin):
    list_display = ("file_id", "file_name", "file_date_scanned", "score", "severity", "exec_parent_count")
    list_filter = ("severity", )
    search_fields = ("file_id", )
    #fields = ("file_id", "severity") # Define what fields can be edited here

    def suit_cell_attributes(self, obj, column):
        if column == 'severity':
            if getattr(obj, "severity") == "low":
                return {'style': 'background-color: rgb(195, 247, 195);'}
            elif getattr(obj, "severity") == "medium":
                return {'style': 'background-color: rgb(255, 255, 175);'}
            elif getattr(obj, "severity") == "high":
                return {'style': 'background-color: rgb(255, 215, 222);'}

@admin.register(DomainIp)
class DomainIpAdmin(admin.ModelAdmin):
    list_display = ("object_id", "object_type", "object_last_updated", "score", "severity", "comm_count", "ref_count")
    list_filter = ("severity", )
    search_fields = ("object_id", )

    def suit_cell_attributes(self, obj, column):
        if column == 'severity':
            if getattr(obj, "severity") == "low":
                return {'style': 'background-color: rgb(195, 247, 195);'}
            elif getattr(obj, "severity") == "medium":
                return {'style': 'background-color: rgb(255, 255, 175);'}
            elif getattr(obj, "severity") == "high":
                return {'style': 'background-color: rgb(255, 215, 222);'}
