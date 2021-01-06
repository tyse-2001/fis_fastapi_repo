from django.test import TestCase

from .models import Files, ExecutionParents, DomainIp, ReferrerFiles, CommunicatingFiles

class FilesModelTests(TestCase):
    def test_file_exists(self):
        Files.objects.create_file(
            file_id="test",
            file_name="test",
            file_date_scanned="test",
            score="test",
            severity="test",
            exec_parent_count=0,
        )
        check = Files.objects.get(file_id="test")
        self.assertIs(bool(check), True)

class ExecutionParentsModelTests(TestCase):
    def test_execution_parent_exists(self):
        ExecutionParents.objects.create_exec_parent(
            parent_id="test",
            related_file_id="test",
            exec_date_scanned="test",
            detection_score="test",
            severity="test",
            parent_type="test",
        )
        check = ExecutionParents.objects.get(parent_id="test")
        self.assertIs(bool(check), True)
    
    def test_fetch_multiple_exec_parent(self):
        ExecutionParents.objects.create_exec_parent(
            parent_id="test",
            related_file_id="test",
            exec_date_scanned="test",
            detection_score="test",
            severity="test",
            parent_type="test",
        )
        ExecutionParents.objects.create_exec_parent(
            parent_id="test2",
            related_file_id="test",
            exec_date_scanned="test2",
            detection_score="test2",
            severity="test2",
            parent_type="test2",
        )
        ExecutionParents.objects.create_exec_parent(
            parent_id="test3",
            related_file_id="test",
            exec_date_scanned="test3",
            detection_score="test3",
            severity="test3",
            parent_type="test3",
        )
        check = ExecutionParents.objects.all().filter(related_file_id="test")

class DomainIpModelTests(TestCase):
    def test_domain_ip_exists(self):
        DomainIp.objects.create_domain_ip(
            object_id="test",
            object_type="test",
            object_last_updated="test",
            score="test",
            severity="test",
            comm_count=0,
            ref_count=0,
        )
        check = DomainIp.objects.get(object_id="test")
        self.assertIs(bool(check), True)

class ReferrerFilesModelTests(TestCase):
    def test_referrer_file_exists(self):
        ReferrerFiles.objects.create_referrer_file(
            ref_file_id="test",
            ref_file_name="test",
            related_object_id="test",
            date_scanned="test",
            detection_score="test",
            severity="test",
            ref_file_type="test",
        )
        check = ReferrerFiles.objects.get(ref_file_id="test")
        self.assertIs(bool(check), True)

    def test_fetch_multiple_ref_file(self):
        ReferrerFiles.objects.create_referrer_file(
            ref_file_id="test",
            ref_file_name="test",
            related_object_id="test",
            date_scanned="test",
            detection_score="test",
            severity="test",
            ref_file_type="test",
        )
        ReferrerFiles.objects.create_referrer_file(
            ref_file_id="test2",
            ref_file_name="test2",
            related_object_id="test",
            date_scanned="test2",
            detection_score="test2",
            severity="test2",
            ref_file_type="test2",
        )
        ReferrerFiles.objects.create_referrer_file(
            ref_file_id="test3",
            ref_file_name="test3",
            related_object_id="test",
            date_scanned="test3",
            detection_score="test3",
            severity="test3",
            ref_file_type="test3",
        )
        check = ReferrerFiles.objects.all().filter(related_object_id="test")
        self.assertIs(bool(check), True)

class CommunicatingFilesModelTests(TestCase):
    def test_communicating_file_exists(self):
        CommunicatingFiles.objects.create_communicating_file(
            comm_file_id="test",
            comm_file_name="test",
            related_object_id="test",
            date_scanned="test",
            detection_score="test",
            severity="test",
            comm_file_type="test",
        )
        check = CommunicatingFiles.objects.get(comm_file_id="test")
        self.assertIs(bool(check), True)
    
    def test_fetch_multiple_comm_file(self):
        CommunicatingFiles.objects.create_communicating_file(
            comm_file_id="test",
            comm_file_name="test",
            related_object_id="test",
            date_scanned="test",
            detection_score="test",
            severity="test",
            comm_file_type="test",
        )
        CommunicatingFiles.objects.create_communicating_file(
            comm_file_id="test2",
            comm_file_name="test2",
            related_object_id="test",
            date_scanned="test2",
            detection_score="test2",
            severity="test2",
            comm_file_type="test2",
        )
        CommunicatingFiles.objects.create_communicating_file(
            comm_file_id="test3",
            comm_file_name="test3",
            related_object_id="test",
            date_scanned="test3",
            detection_score="test3",
            severity="test3",
            comm_file_type="test3",
        )
        check = CommunicatingFiles.objects.all().filter(related_object_id="test")
        self.assertIs(bool(check), True)