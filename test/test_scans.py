from nessus.editor import NessusTemplateType
from nessus.error import NessusError
from test import TestBase


class TestScans(TestBase):
    def test_list(self):
        self.nessus.scans.list()

    def test_create(self):
        old_scans = {s.id for s in self.nessus.scans.list()}
        templates = self.nessus.editor.list(NessusTemplateType.scan)
        template = next(t for t in templates if t.name == 'basic')

        created = self.nessus.scans.create(template)

        new_scans = {s.id for s in self.nessus.scans.list()}
        old_scans.add(created.id)
        self.assertSetEqual(new_scans, old_scans)

    def test_create_empty_name(self):
        templates = self.nessus.editor.list(NessusTemplateType.scan)
        template = next(t for t in templates if t.name == 'basic')

        self.assertRaises(NessusError, self.nessus.scans.create, template, name='')

    def test_create_multi_targets(self):
        old_scans = {s.id for s in self.nessus.scans.list()}
        templates = self.nessus.editor.list(NessusTemplateType.scan)
        template = next(t for t in templates if t.name == 'basic')

        created = self.nessus.scans.create(template, default_targets=['localhost', '127.0.0.1', '::1'])

        new_scans = {s.id for s in self.nessus.scans.list()}
        old_scans.add(created.id)
        self.assertSetEqual(new_scans, old_scans)
