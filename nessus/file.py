from nessus.base import LibNessusBase


class NessusFile:
    def __init__(self, path: str) -> None:
        self.path = path


class NessusRemoteFile:
    def __init__(self, name: str) -> None:
        self.name = name


class LibNessusFile(LibNessusBase):
    def upload(self, nessus_file: NessusFile) -> NessusRemoteFile:
        """
        Uploads a file.
        ~lies: the data field name 'Filedata' is not documented in Nessus
        :param nessus_file: file to upload
        :return: the filename on nessus
        """
        return NessusRemoteFile('empty')
