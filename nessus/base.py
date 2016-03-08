import re

import requests
from typing import Optional, Mapping, IO

from nessus.error import NessusInternalServerError, NessusError, NessusPolicyInUseError, \
    NessusDuplicateFilenameLimitError


class LibNessusBase:
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
        self.__url = url
        self.__api_access_key = api_access_key
        self.__api_secret_key = api_secret_key

        self.__get_session_cache = None

    def __get_session(self) -> requests.Session:
        """
        return a session with some useful fields already set
        :return: session object suitable to connect to nessus
        """

        if self.__get_session_cache is not None:
            return self.__get_session_cache

        session = requests.Session()

        session.headers['X-ApiKeys'] = 'accessKey={}; secretKey={};'.format(self.__api_access_key,
                                                                            self.__api_secret_key)

        self.__get_session_cache = session
        return session

    def __request(self, method: str, path: str, **kwargs) -> requests.Response:
        session = self.__get_session()
        url = '{}/{}'.format(self.__url, path)

        ans = session.request(method=method, url=url, verify=False, **kwargs)
        self.__check_error(ans)

        return ans

    def _get(self, path: str) -> requests.Response:
        """
        GET request to nessus
        :param path: path in nessus ('https://localhost:8834/file/upload' -> 'file/upload')
        :return: response from requests
        """
        return self.__request('GET', path)

    def _delete(self, path: str) -> requests.Response:
        """
        DELETE request to nessus
        :param path: path in nessus ('https://localhost:8834/file/upload' -> 'file/upload')
        :return: response from requests
        """
        return self.__request('DELETE', path)

    def _post(self, path: str, json: Optional[Mapping[str, str]] = None,
              files: Optional[IO[bytes]] = None) -> requests.Response:
        """
        POST request to nessus
        :param path: path in nessus ('https://localhost:8834/file/upload' -> 'file/upload')
        :param json: POST data to pass to requests
        :param file_bytes: opened file to passe to requests
        :return: response from requests
        """
        return self.__request('POST', path, json=json, files=files)

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
