"""
sub modules for everything about the policies
"""
from enum import Enum
from uuid import uuid4

from typing import Iterable, Mapping, Union, Tuple, Optional

from nessus.base import LibNessusBase
from nessus.editor import NessusTemplate
from nessus.file import NessusRemoteFile
from nessus.model import lying_exist, Object


class NessusPolicyVisibility(Enum):
    """
    should be int value but nessus is lying
    """
    private = 'private'
    shared = 'shared'


class NessusPolicy(Object):
    """
    nessus is lying with:
     - `visibility` which is not always there and which is an int
    """

    # pylint: disable=too-many-instance-attributes
    # pylint: disable=too-few-public-methods

    # pylint: disable=too-many-arguments
    def __init__(self, policy_id: int, template_uuid: str, name: str, description: str, owner_id: str, owner: str,
                 shared: int, user_permissions: int, creation_date: int, last_modification_date: int,
                 visibility: NessusPolicyVisibility, no_target: bool) -> None:
        self.id = policy_id  # pylint: disable= invalid-name
        self.template_uuid = template_uuid
        self.name = name
        self.description = description
        self.owner_id = owner_id
        self.owner = owner
        self.shared = shared
        self.user_permissions = user_permissions
        self.creation_date = creation_date
        self.last_modification_date = last_modification_date
        self.visibility = visibility
        self.no_target = no_target

    def __eq__(self, other):
        return isinstance(other, NessusPolicy) and self.id == other.id

    def __hash__(self):
        return hash(self.id)

    # pylint: disable=too-many-arguments
    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusPolicy':
        """
        generate a NessusPolicy by parsing the given json
        :param json_dict: json encoded NessusPolicy
        :return: extracted NessusPolicy
        """
        policy_id = int(json_dict['id'])
        template_uuid = str(json_dict['template_uuid'])
        name = str(json_dict['name'])
        description = str(json_dict['description'])
        owner_id = str(json_dict['owner_id'])
        owner = str(json_dict['owner'])
        shared = int(json_dict['shared'])
        user_permissions = int(json_dict['user_permissions'])
        creation_date = int(json_dict['creation_date'])
        last_modification_date = int(json_dict['last_modification_date'])
        visibility = lying_exist(json_dict, 'visibility', NessusPolicyVisibility, None)
        no_target = bool(json_dict['no_target'])

        return NessusPolicy(policy_id, template_uuid, name, description, owner_id, owner, shared, user_permissions,
                            creation_date, last_modification_date, visibility, no_target)


class LibNessusPolicies(LibNessusBase):
    """
    modules handling /policies
    """

    def list(self) -> Iterable[NessusPolicy]:
        """
        Returns the policy list.
        :return: iterable of available policy
        """
        ans = self._get('policies')
        return {NessusPolicy.from_json(policy) for policy in ans.json()['policies']}

    def delete(self, policy: NessusPolicy) -> None:
        """
        Delete a policy.
        :param policy: one to delete
        """
        url = 'policies/{}'.format(policy.id)
        self._delete(url)

    # pylint: disable=bad-whitespace
    def create(self, template: NessusTemplate, name: Optional[str] = None) -> Tuple[int, str]:
        """
        Creates a policy.
        :param template: what to create
        :param name: name of the policy
        :return: (policy_id, policy_name)
        """
        if name is None:
            name = str(uuid4())

        json = {
            'uuid': template.uuid,
            'settings': {
                'name': name
            },
            'audits': {},
        }
        ans = self._post('policies', json=json)
        return ans.json()['policy_id'], ans.json()['policy_name']

    def import_(self, remote_file: NessusRemoteFile) -> NessusPolicy:
        """
        Import an existing policy uploaded using Nessus.file (.nessus format only).
        sorry about the name, but in python 'import' is a reserved keyword
        :param remote_file: file to treat as nessus policy
        """
        json = {'file': remote_file.name}
        ans = self._post('policies/import', json=json)
        return NessusPolicy.from_json(ans.json())
