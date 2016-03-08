from os import environ
from unittest import TestCase

from nessus import LibNessus


class TestBase(TestCase):
    def setUp(self):
        url = environ['NESSUS_URL']
        api_access_key = environ['NESSUS_ACCESS_KEY']
        api_secret_key = environ['NESSUS_SECRET_KEY']

        self.nessus = LibNessus(url=url, api_access_key=api_access_key, api_secret_key=api_secret_key)
