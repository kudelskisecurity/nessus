from enum import Enum
from uuid import uuid4

from typing import Iterable, Mapping, Union, Tuple

from nessus.base import LibNessusBase
from nessus.editor import NessusTemplate
from nessus.file import NessusRemoteFile
from nessus.model import lying_exist


class NessusPolicyVisibility(Enum):
    """
    should be int value but nessus is lying
    """
    private = 'private'
    shared = 'shared'


class NessusPolicy:
    """
    nessus is lying with:
     - `visibility` which is not always there and which is an int
    """

    def __init__(self, policy_id: int, template_uuid: str, name: str, description: str, owner_id: str, owner: str,
                 shared: int,
                 user_permissions: int, creation_date: int, last_modification_date: int, visibility: int,
                 no_target: bool) -> None:
        self.id = policy_id
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

    def __repr__(self) -> str:
        form = 'NessusPolicy({id!r}, {template_uuid!r}, {name!r}, {description!r}, {owner_id!r}, {owner!r}, ' \
               '{shared!r}, {user_permissions!r}, {creation_date!r}, {last_modification_date!r}, {visibility!r}, ' \
               '{no_target!r})'
        return form.format(**self.__dict__)

    def __eq__(self, other):
        return isinstance(other, NessusPolicy) and self.id == other.id

    def __hash__(self):
        return hash(self.id)

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusPolicy':
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
        visibility = lying_exist(json_dict, 'visibility', NessusPolicyVisibility)
        no_target = bool(json_dict['no_target'])

        return NessusPolicy(policy_id, template_uuid, name, description, owner_id, owner, shared, user_permissions,
                            creation_date, last_modification_date, visibility, no_target)


class LibNessusPolicies(LibNessusBase):
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

    def create(self, template: NessusTemplate, name: str = str(uuid4())) -> Tuple[int, str]:
        """
        Creates a policy.
        :param template: what to create
        :param name: name of the policy
        :return: (policy_id, policy_name)
        """
        json = {
            'uuid': template.uuid,
            'settings': {
                'name': name
            },
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
