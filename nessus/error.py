import requests


class NessusError(Exception):
    """
    generic error from nessus
    """

    def __init__(self, response: requests.Response) -> None:
        """
        wrap some useful information
        :param response: response we got from nessus, in which there _must_ be json with an 'error' field
        """
        assert 'error' in response.json()
        super().__init__(response.json()['error'])
        self.response = response


class NessusInternalServerError(NessusError):
    """
    internal server error
    """
    pass


class NessusPolicyInUseError(NessusError):
    def __init__(self, response: requests.Response, policy_name: str, policy_id: int) -> None:
        super().__init__(response)
        self.policy_name = policy_name
        self.policy_id = policy_id


class NessusDuplicateFilenameLimitError(NessusError):
    def __init__(self, response: requests.Response, filename: int) -> None:
        super().__init__(response)
        self.filename = filename
