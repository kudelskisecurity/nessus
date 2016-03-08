from nessus.file import LibNessusFile
from nessus.policies import LibNessusPolicies
from nessus.scans import LibNessusScans


class LibNessus:
    def __init__(self, url: str, api_access_key: str, api_secret_key: str) -> None:
        args = {
            'url': url,
            'api_access_key': api_access_key,
            'api_secret_key': api_secret_key,
        }
        self.file = LibNessusFile(**args)
        self.scans = LibNessusScans(**args)
        self.policies = LibNessusPolicies(**args)
