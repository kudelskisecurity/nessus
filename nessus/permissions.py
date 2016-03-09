from enum import Enum

from typing import Mapping, Union

from nessus.error import NessusError
from nessus.model import Object, lying_type


class NessusPermissionType(Enum):
    default = 'default'
    user = 'user'
    group = 'group'


class NessusPermissionValueError(NessusError):
    def __init__(self, value: int) -> None:
        super().__init__()
        self.value = int


class NessusPermission(Object):
    """
    lies:
     - `owner` could be None
     - `permissions_id` could be None
    """

    def __init__(self, owner: int, permission_type: str, permissions: int, permission_id: int, name: str) -> None:
        if permissions not in (0, 16, 32, 64, 128):
            raise NessusPermissionValueError(permissions)

        self.owner = owner
        self.type = permission_type
        self.permissions = permissions
        self.id = permission_id
        self.name = name

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusPermission':
        owner = lying_type(json_dict['owner'], int)  # it's None actually
        permission_type = str(json_dict['type'])
        permissions = int(json_dict['permissions'])
        permission_id = lying_type(json_dict['id'], int)  # it's None actually
        name = str(json_dict['name'])

        return NessusPermission(owner, permission_type, permissions, permission_id, name)
