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

class ExecutionParentsManager(models.Manager):
    def create_exec_parent(
        self,
        parent_id,
        related_file_id,
        exec_date_scanned,
        detection_score,
        severity,
        parent_type
    ):
        exec_parent_entry = self.create(
            parent_id=parent_id,
            related_file_id=related_file_id,
            exec_date_scanned=exec_date_scanned,
            detection_score=detection_score,
            severity=severity,
            parent_type=parent_type,
        )
        return exec_parent_entry
class ExecutionParents(models.Model):
    parent_id = models.CharField(max_length=64)
    related_file_id = models.CharField(max_length=64)
    exec_date_scanned = models.CharField(max_length=23)
    detection_score = models.CharField(max_length=7)
    severity = models.CharField(max_length=6)
    parent_type = models.CharField(max_length=255)

    objects = ExecutionParentsManager()

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

class ReferrerFilesManager(models.Manager):
    def create_referrer_file(
        self,
        ref_file_id,
        ref_file_name,
        related_object_id,
        date_scanned,
        detection_score,
        severity,
        ref_file_type
    ):
        referrer_file_entry = self.create(
            ref_file_id=ref_file_id,
            ref_file_name=ref_file_name,
            related_object_id=related_object_id,
            date_scanned=date_scanned,
            detection_score=detection_score,
            severity=severity,
            ref_file_type=ref_file_type,
        )
        return referrer_file_entry
class ReferrerFiles(models.Model):
    ref_file_id = models.CharField(max_length=64)
    ref_file_name = models.TextField()
    related_object_id = models.CharField(max_length=255)
    date_scanned = models.CharField(max_length=23)
    detection_score = models.CharField(max_length=7)
    severity = models.CharField(max_length=6)
    ref_file_type = models.CharField(max_length=255)

    objects = ReferrerFilesManager()

class CommunicatingFilesManager(models.Manager):
    def create_communicating_file(
        self,
        comm_file_id,
        comm_file_name,
        related_object_id,
        date_scanned,
        detection_score,
        severity,
        comm_file_type
    ):
        communciating_file_entry = self.create(
            comm_file_id=comm_file_id,
            comm_file_name=comm_file_name,
            related_object_id=related_object_id,
            date_scanned=date_scanned,
            detection_score=detection_score,
            severity=severity,
            comm_file_type=comm_file_type,
        )
        return communciating_file_entry
class CommunicatingFiles(models.Model):
    comm_file_id = models.CharField(max_length=64)
    comm_file_name = models.TextField()
    related_object_id = models.CharField(max_length=255)
    date_scanned = models.CharField(max_length=23)
    detection_score = models.CharField(max_length=7)
    severity = models.CharField(max_length=6)
    comm_file_type = models.CharField(max_length=255)

    objects = CommunicatingFilesManager()