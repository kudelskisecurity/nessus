import re
from uuid import uuid4

import requests
from typing import Optional, Mapping, IO, Iterable

from nessus.error import NessusInternalServerError, NessusError, NessusPolicyInUseError, \
    NessusDuplicateFilenameLimitError
from nessus.file import NessusFile, NessusRemoteFile
from nessus.model import NessusPolicy, NessusScan


class LibNessus:
    """
    entry point for the nessus library, welcome!
    """

    def __init__(self, url: str, api_access_key: str, api_secret_key: str) -> None:
        """
        create a nessus session with the given credentials
        :param url: url (so with 'https' and stuff) to access nessus
        :param api_access_key: access key to the API
        :param api_secret_key: secret key to the API
        """
        self.url = url
        self.api_access_key = api_access_key
        self.api_secret_key = api_secret_key

    def file_upload(self, nessus_file: NessusFile) -> NessusRemoteFile:
        """
        Uploads a file.
        :param nessus_file: file to upload
        :return: the filename on nessus
        """
        with open(nessus_file.path, 'rb') as io:
            ans = self.__post(path='file/upload', file_bytes=io)
            filename = ans.json()['fileuploaded']
            return NessusRemoteFile(filename)

    def policies_list(self) -> Iterable[NessusPolicy]:
        """
        get the list of policy
        :return: iterable of available policy
        """
        ans = self.__get('policies')
        return {NessusPolicy.from_json(policy) for policy in ans.json()['policies']}

    def policies_delete(self, policy: NessusPolicy) -> None:
        url = 'policies/{}'.format(policy.id)
        self.__delete(url)

    def policies_import(self, remote_file: NessusRemoteFile) -> NessusPolicy:
        data = {'file': remote_file.name}
        ans = self.__post('policies/import', data=data)
        return NessusPolicy.from_json(ans.json())

    def scans_list(self) -> Iterable[NessusScan]:
        ans = self.__get('scans')

        if ans.json()['scans'] is None:
            return set()

        return {NessusScan.from_json(elem) for elem in ans.json()['scans']}


    # TODO dynamic programming
    def __get_session(self) -> requests.Session:
        """
        return a session with some useful fields already set
        :return: session object suitable to connect to nessus
        """
        session = requests.Session()

        session.headers['X-ApiKeys'] = 'accessKey={}; secretKey={};'.format(self.api_access_key, self.api_secret_key)

        return session

    def __get(self, path: str) -> requests.Response:
        """
        GET request to nessus
        :param path: path in nessus ('https://localhost:8834/file/upload' -> 'file/upload')
        :return: response from requests
        """
        session = self.__get_session()
        url = '{}/{}'.format(self.url, path)

        ans = session.get(url=url, verify=False)
        self.__check_error(ans)

        return ans

    def __delete(self, path: str) -> requests.Response:
        """
        DELETE request to nessus
        :param path: path in nessus ('https://localhost:8834/file/upload' -> 'file/upload')
        :return: response from requests
        """
        session = self.__get_session()
        url = '{}/{}'.format(self.url, path)

        ans = session.delete(url=url, verify=False)
        self.__check_error(ans)

        return ans

    def __post(self, path: str, data: Optional[Mapping[str, str]] = None,
               file_bytes: Optional[IO[bytes]] = None) -> requests.Response:
        """
        POST request to nessus
        :param path: path in nessus ('https://localhost:8834/file/upload' -> 'file/upload')
        :param data: POST data to pass to requests
        :param file_bytes: opened file to passe to requests
        :return: response from requests
        """
        session = self.__get_session()
        url = '{}/{}'.format(self.url, path)
        if file_bytes is None:
            files = None
        else:
            # by generating a random name, we avoid limit of number of upload
            filename = str(uuid4())
            files = {
                'Filedata': (filename, file_bytes)
            }

        ans = session.post(url=url, data=data, files=files, verify=False)
        self.__check_error(ans)

        return ans

    @staticmethod
    def __check_error(response: requests.Response) -> None:
        """
        raise an error if needed
        :param response: response got from nessus
        """

        if response.status_code == 200:
            return

        if (not response.text.startswith('{')) or ('error' not in response.json()):
            raise NessusError(response=response)

        error_str = response.json()['error']

        if error_str == 'An internal server error occurred':
            raise NessusInternalServerError(response=response)

        regex = {
            'Policy "([^"]+)" \(ID (\d+)\) cannot be deleted since it is currently used by one or more scans.':
                NessusPolicyInUseError,
            "could not upload file '([^']+)': duplicate filename limit exceeded":
                NessusDuplicateFilenameLimitError,
        }

        regex_compiled = {re.compile(k): v for k, v in regex.items()}
        for reg, excep in regex_compiled.items():
            match = reg.match(error_str)
            if match:
                args = (response,) + match.groups()
                raise excep(*args)

        raise NessusError(response=response)
