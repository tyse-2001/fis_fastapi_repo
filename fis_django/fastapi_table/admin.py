from django.contrib import admin

from .models import DomainIp, ReferrerFiles, CommunicatingFiles, Files, ExecutionParents

# Register your models here.

@admin.register(Files)
class FilesAdmin(admin.ModelAdmin):
    change_list_template = "admin/extend_changelist.html"

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

@admin.register(ExecutionParents)
class ExecutionParentsAdmin(admin.ModelAdmin):
    change_list_template = "admin/extend_changelist.html"

    list_display = ("parent_id", "related_file_id", "exec_date_scanned", "detection_score", "severity", "parent_type")
    list_filter = ("severity", )
    search_fields = ("parent_id", )

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
    change_list_template = "admin/extend_changelist.html"

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

@admin.register(ReferrerFiles)
class ReferrerFilesAdmin(admin.ModelAdmin):
    change_list_template = "admin/extend_changelist.html"

    list_display = ("ref_file_id", "ref_file_name", "related_object_id", "date_scanned", "detection_score", "severity", "ref_file_type")
    list_filter = ("severity", )
    search_fields = ("ref_file_id", )

    def suit_cell_attributes(self, obj, column):
        if column == 'severity':
            if getattr(obj, "severity") == "low":
                return {'style': 'background-color: rgb(195, 247, 195);'}
            elif getattr(obj, "severity") == "medium":
                return {'style': 'background-color: rgb(255, 255, 175);'}
            elif getattr(obj, "severity") == "high":
                return {'style': 'background-color: rgb(255, 215, 222);'}

@admin.register(CommunicatingFiles)
class CommunicatingFilesAdmin(admin.ModelAdmin):
    change_list_template = "admin/extend_changelist.html"

    list_display = ("comm_file_id", "comm_file_name", "related_object_id", "date_scanned", "detection_score", "severity", "comm_file_type")
    list_filter = ("severity", )
    search_fields = ("comm_file_id", )

    def suit_cell_attributes(self, obj, column):
        if column == 'severity':
            if getattr(obj, "severity") == "low":
                return {'style': 'background-color: rgb(195, 247, 195);'}
            elif getattr(obj, "severity") == "medium":
                return {'style': 'background-color: rgb(255, 255, 175);'}
            elif getattr(obj, "severity") == "high":
                return {'style': 'background-color: rgb(255, 215, 222);'}