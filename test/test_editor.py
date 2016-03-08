from nessus.editor import NessusTemplateType
from test import TestBase


class TestEditor(TestBase):
    def test_list_scan(self):
        template_type = NessusTemplateType.scan

        templates = self.nessus.editor.list(template_type)

        self.assertGreater(len(templates), 0)
