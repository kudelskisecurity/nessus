from tempfile import NamedTemporaryFile

from nessus.file import NessusFile
from test import TestBase


class TestFile(TestBase):
    def test_upload_empty_file(self):
        with NamedTemporaryFile() as tmpfile:
            file = NessusFile(path=tmpfile.name)

            self.nessus.file.upload(file)
