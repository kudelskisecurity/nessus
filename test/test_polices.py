import os

from nessus.editor import NessusTemplateType
from nessus.file import NessusFile
from test import TestBase


class TestPolicies(TestBase):

    def test_list_return_same_items(self):
        old_policies = self.nessus.policies.list()
        new_policies = self.nessus.policies.list()

        self.assertSetEqual(set(new_policies), set(old_policies))

    def test_upload(self):
        local_file = NessusFile(os.path.join(self.data_dir, 'glibc'))
        old_policies = self.nessus.policies.list()

        remote_file = self.nessus.file.upload(local_file)
        new_policy = self.nessus.policies.import_(remote_file)
        self.added_policies.add(new_policy)

        new_policies = self.nessus.policies.list()
        self.assertEqual(len(new_policies), len(old_policies) + 1)
        self.assertIn(new_policy, new_policies)

    def test_create(self):
        old_policies = {p.id for p in self.nessus.policies.list()}
        templates = self.nessus.editor.list(NessusTemplateType.policy)
        template = next(t for t in templates if t.name == 'discovery')

        policy_id, policy_name = self.nessus.policies.create(template)
        self.__add_policy_id_to_remove(policy_id)

        new_policies = {p.id for p in self.nessus.policies.list()}
        self.assertIn(policy_id, new_policies)

        old_policies.add(policy_id)
        self.assertSetEqual(old_policies, new_policies)

    def __add_policy_id_to_remove(self, policy_id: int) -> None:
        class P:
            pass

        p = P()
        p.id = policy_id
        self.added_policies.add(p)

    def test_delete(self):
        local_file = NessusFile(os.path.join(self.data_dir, 'glibc'))
        old_policies = self.nessus.policies.list()
        remote_file = self.nessus.file.upload(local_file)
        new_policy = self.nessus.policies.import_(remote_file)

        self.nessus.policies.delete(new_policy)

        new_policies = self.nessus.policies.list()
        self.assertSetEqual(set(new_policies), set(old_policies))
