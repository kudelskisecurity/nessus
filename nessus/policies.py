from typing import Iterable

from nessus.base import LibNessusBase
from nessus.file import NessusRemoteFile
from nessus.model import NessusPolicy


class LibNessusPolicies(LibNessusBase):
    def list(self) -> Iterable[NessusPolicy]:
        """
        get the list of policy
        :return: iterable of available policy
        """
        ans = self._get('policies')
        return {NessusPolicy.from_json(policy) for policy in ans.json()['policies']}

    def delete(self, policy: NessusPolicy) -> None:
        url = 'policies/{}'.format(policy.id)
        self._delete(url)

    def import_(self, remote_file: NessusRemoteFile) -> NessusPolicy:
        """
        import the given file as a policy
        sorry about the name, but in python 'import' is a reserved keyword
        :param remote_file: file to treat as nessus policy
        """
        data = {'file': remote_file.name}
        ans = self._post('policies/import', data=data)
        return NessusPolicy.from_json(ans.json())
