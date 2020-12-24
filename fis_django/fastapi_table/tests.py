from django.test import TestCase

from .models import Files, DomainIp

# Create your tests here.
class DatabaseFetchValues(TestCase):
    def test_files_table_values_exist(self):
        """
        There are values in the django files model and returns True
        """
        entry = Files.objects.create_file(
            "test",
            "test",
            "test",
            "test",
            "test",
            0,
        )
        files_value = Files.objects.get(file_id="test")
        self.assertEqual(files_value.file_id, "test")
    
    def test_domain_ip_values_exist(self):
        """
        There are values in the django domain_ip model and returns True
        """
        entry = DomainIp.objects.create_domain_ip(
            "test",
            "test",
            "test",
            "test",
            "test",
            0,
            0,
        )
        domain_ip_value = DomainIp.objects.get(object_id="test")
        self.assertEqual(domain_ip_value.object_id, "test")
