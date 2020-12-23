from django.db import models

# Create your models here.

class FilesManager(models.Manager):
    def create_file(
        self,
        file_id,
        file_name,
        file_date_scanned,
        score,
        severity,
        exec_parent_count
    ):
        file_entry = self.create(
            file_id=file_id,
            file_name=file_name,
            file_date_scanned=file_date_scanned,
            score=score,
            severity=severity,
            exec_parent_count=exec_parent_count,
        )
        return file_entry

class Files(models.Model):
    file_id = models.CharField(max_length=64)
    file_name = models.TextField()
    file_date_scanned = models.CharField(max_length=23)
    score = models.CharField(max_length=7)
    severity = models.CharField(max_length=6)
    exec_parent_count = models.IntegerField()

    objects = FilesManager()

class DomainIpManager(models.Manager):
    def create_domain_ip(
        self,
        object_id,
        object_type,
        object_last_updated,
        score,
        severity,
        comm_count,
        ref_count
    ):
        domain_ip_entry = self.create(
            object_id=object_id,
            object_type=object_type,
            object_last_updated=object_last_updated,
            score=score,
            severity=severity,
            comm_count=comm_count,
            ref_count=ref_count,
        )
        return domain_ip_entry

class DomainIp(models.Model):
    object_id = models.CharField(max_length=255)
    object_type = models.CharField(max_length=10)
    object_last_updated = models.CharField(max_length=23)
    score = models.CharField(max_length=7)
    severity = models.CharField(max_length=6)
    comm_count = models.IntegerField()
    ref_count = models.IntegerField()

    objects = DomainIpManager()
