"""
error generated from nessus, everything derive from NessusError
"""
import requests


class NessusError(Exception):
    """
    generic error from nessus
    """


class NessusNetworkError(NessusError):
    def __init__(self, response: requests.Response) -> None:
        """
        wrap some useful information
        :param response: response we got from nessus, in which there _must_ be json with an 'error' field
        """
        assert 'error' in response.json()
        super().__init__(response.json()['error'])
        self.response = response


class NessusInternalServerError(NessusNetworkError):
    """
    internal server error
    """
    pass


class NessusScanIsActiveError(NessusNetworkError):
    """
    scan is active (usually when wanting to delete it)
    """
    pass


class NessusPolicyInUseError(NessusNetworkError):
    """
    policy in use (usually when wanting to delete it)
    """

    def __init__(self, response: requests.Response, policy_name: str, policy_id: int) -> None:
        super().__init__(response)
        self.policy_name = policy_name
        self.policy_id = policy_id


class NessusDuplicateFilenameLimitError(NessusNetworkError):
    """
    if you upload to much file with the same filename, it will fail
    """

    def __init__(self, response: requests.Response, filename: int) -> None:
        super().__init__(response)
        self.filename = filename
