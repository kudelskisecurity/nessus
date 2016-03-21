"""
entry point of nessus modules
it should be quite mapped to the official REST API, but sometimes, I changed it to more sensible inputs. it is also
documented where the REST API is lying.
"""

from nessus.editor import LibNessusEditor
from nessus.file import LibNessusFile
from nessus.policies import LibNessusPolicies
from nessus.scans import LibNessusScans


class LibNessus:
    """
    gather all the submodules to be able to have a nice way to acces it, for example: `nessus.policies.list()`
    """
    # pylint: disable=too-few-public-methods

    def __init__(self, host: str, port: int, api_access_key: str, api_secret_key: str) -> None:
        args = {
            'host': host,
            'port': port,
            'api_access_key': api_access_key,
            'api_secret_key': api_secret_key,
        }

        self.file = LibNessusFile(**args)
        self.scans = LibNessusScans(**args)
        self.policies = LibNessusPolicies(**args)
        self.editor = LibNessusEditor(**args)
