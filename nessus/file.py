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
        :param nessus_file: file to upload
        :return: the filename on nessus
        """
        with open(nessus_file.path, 'rb') as io:
            ans = self._post(path='file/upload', file_bytes=io)
            filename = ans.json()['fileuploaded']
            return NessusRemoteFile(filename)
