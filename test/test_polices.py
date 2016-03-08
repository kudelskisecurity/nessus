from nessus import NessusFile
from test import TestBase


class TestPolicies(TestBase):
    def setUp(self):
        super().setUp()
        self.added_policies = set()

    def tearDown(self):
        super().tearDown()

        for policy in self.added_policies:
            self.nessus.policies_delete(policy)

    def test_policies_list_return_same_items(self):
        old_policies = self.nessus.policies_list()
        new_policies = self.nessus.policies_list()

        self.assertSetEqual(set(new_policies), set(old_policies))

    def test_policies_upload(self):
        local_file = NessusFile('test/data/glibc')
        old_policies = self.nessus.policies_list()

        remote_file = self.nessus.file_upload(local_file)
        new_policy = self.nessus.policies_import(remote_file)
        self.added_policies.add(new_policy)

        new_policies = self.nessus.policies_list()
        self.assertEqual(len(new_policies), len(old_policies) + 1)
        self.assertIn(new_policy, new_policies)

    def test_policies_delete(self):
        local_file = NessusFile('test/data/glibc')
        old_policies = self.nessus.policies_list()
        remote_file = self.nessus.file_upload(local_file)
        new_policy = self.nessus.policies_import(remote_file)

        self.nessus.policies_delete(new_policy)

        new_policies = self.nessus.policies_list()
        self.assertSetEqual(set(new_policies), set(old_policies))
