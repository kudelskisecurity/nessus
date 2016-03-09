from os import environ
from unittest import TestCase

from nessus import LibNessus


class TestBase(TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data_dir = 'test/data'


    def setUp(self):
        url = environ['NESSUS_URL']
        api_access_key = environ['NESSUS_ACCESS_KEY']
        api_secret_key = environ['NESSUS_SECRET_KEY']

        self.nessus = LibNessus(url=url, api_access_key=api_access_key, api_secret_key=api_secret_key)

        self.added_policies = set()
        self.added_policies_id = set()
        self.added_scans = set()

    def tearDown(self):
        super().tearDown()

        for scan in self.added_scans:
            self.nessus.scans.delete(scan)

        self.added_policies |= {p for p in self.nessus.policies.list() if p.id in self.added_policies_id}
        for policy in self.added_policies:
            self.nessus.policies.delete(policy)
