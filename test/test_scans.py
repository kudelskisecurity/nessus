from typing import Optional

from nessus.editor import NessusTemplateType, NessusTemplate
from nessus.error import NessusError
from test import TestBase


class TestScans(TestBase):
    def test_list(self):
        self.nessus.scans.list()

    def __get_template(self, name: str = 'basic'):
        templates = self.nessus.editor.list(NessusTemplateType.scan)
        return next(t for t in templates if t.name == name)

    def __get_scans_id(self):
        return {s.id for s in self.nessus.scans.list()}

    def __get_policy(self, template: Optional[NessusTemplate] = None):
        if template is None:
            template = self.__get_template()
        policy_id, policy_ = self.nessus.policies.create(template)
        policies = self.nessus.policies.list()
        return next(p for p in policies if p.id == policy_id)

    def test_create(self):
        old_scans = self.__get_scans_id()
        policy = self.__get_policy()

        created = self.nessus.scans.create(policy)

        self.assertEqual(created.policy_id, policy.id)

        new_scans = self.__get_scans_id()
        old_scans.add(created.id)
        self.assertSetEqual(new_scans, old_scans)

    def test_create_override_template(self):
        old_scans = self.__get_scans_id()
        template_policy = self.__get_template()
        template_other = self.__get_template('drown')
        policy = self.__get_policy(template_policy)

        created = self.nessus.scans.create(policy, template=template_other)

        new_scans = self.__get_scans_id()
        old_scans.add(created.id)
        self.assertSetEqual(new_scans, old_scans)

    def test_create_empty_name(self):
        policy = self.__get_policy()

        self.assertRaises(NessusError, self.nessus.scans.create, policy, name='')

    def test_create_multi_targets(self):
        old_scans = self.__get_scans_id()
        policy = self.__get_policy()

        created = self.nessus.scans.create(policy, default_targets=['localhost', '127.0.0.1', '::1'])

        new_scans = self.__get_scans_id()
        old_scans.add(created.id)
        self.assertSetEqual(new_scans, old_scans)
