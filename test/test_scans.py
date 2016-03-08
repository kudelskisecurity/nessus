from test import TestBase


class TestScans(TestBase):
    def test_scans_list(self):
        self.nessus.scans.list()
