from typing import Mapping, Union, Optional


class NessusPolicy:
    """
    nessus is lying with:
     - `visibility` which is not always there, and is not an int
    """

    def __init__(self, policy_id: int, template_uuid: str, name: str, description: str, owner_id: str, owner: str,
                 shared: int, user_permissions: int, creation_date: int, last_modification_date: int,
                 visibility: Optional[int]) -> None:
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

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if not isinstance(other, NessusPolicy):
            return False
        return self.id == other.id

    def __repr__(self) -> str:
        form = 'NessusPolicy({id!r}, {template_uuid!r}, {name!r}, {description!r}, {owner_id!r}, {owner!r}, ' \
               '{shared!r}, {user_permissions!r}, {creation_date!r}, {last_modification_date!r}, {visibility!r})'
        return form.format(**self.__dict__)

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

        if 'visibility' in json_dict:
            visibility = str(json_dict['visibility'])
        else:
            visibility = None

        return NessusPolicy(policy_id, template_uuid, name, description, owner_id, owner, shared, user_permissions,
                            creation_date, last_modification_date, visibility)


class NessusScan:
    def __init__(self, scan_id: int, uuid: str, name: str, owner: str, enabled: bool, folder_id: int, read: bool,
                 status: str, shared: bool, user_permissions: int, creation_date: int, last_modification_date: int,
                 control: bool, starttime: str, timezone: str, rrules: str) -> None:
        self.id = scan_id
        self.uuid = uuid
        self.name = name
        self.owner = owner
        self.enabled = enabled
        self.folder_id = folder_id
        self.read = read
        self.status = status
        self.shared = shared
        self.user_permissions = user_permissions
        self.creation_date = creation_date
        self.last_modification_date = last_modification_date
        self.control = control
        self.starttime = starttime
        self.timezone = timezone
        self.rrules = rrules

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if not isinstance(other, NessusScan):
            return False
        return self.id == other.id

    def __repr__(self) -> str:
        form = 'NessusScan({uuid!r}, {uuid!r}, {name!r}, {owner!r}, {enabled!r}, {folder_id!r}, {read!r}, ' \
               '{status!r}, {shared!r}, {user_permissions!r}, {creation_date!r}, {last_modification_date!r}, ' \
               '{control!r}, {starttime!r}, {timezone!r}, {rrules!r})'
        return form.format(**self.__dict__)

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScan':
        scan_id = int(json_dict['id'])
        uuid = str(json_dict['uuid'])
        name = str(json_dict['name'])
        owner = str(json_dict['owner'])
        enabled = bool(json_dict['enabled'])
        folder_id = int(json_dict['folder_id'])
        read = bool(json_dict['read'])
        status = str(json_dict['status'])
        shared = bool(json_dict['shared'])
        user_permissions = int(json_dict['user_permissions'])
        creation_date = int(json_dict['creation_date'])
        last_modification_date = int(json_dict['last_modification_date'])
        control = bool(json_dict['control'])
        starttime = str(json_dict['starttime'])
        timezone = str(json_dict['timezone'])
        rrules = str(json_dict['rrules'])

        return NessusScan(scan_id, uuid, name, owner, enabled, folder_id, read, status, shared, user_permissions,
                          creation_date, last_modification_date, control, starttime, timezone, rrules)


class NessusTemplate:
    def __init__(self, uuid: str, name: str, title: str, description: str, cloud_only: bool, subscription_only: bool,
                 is_agent: bool) -> None:
        self.uuid = uuid
        self.name = name
        self.title = title
        self.description = description
        self.cloud_only = cloud_only
        self.subscription_only = subscription_only
        self.is_agent = is_agent

    def __repr__(self) -> str:
        form = 'NessusTemplate({uuid!r}, {name!r}, {title!r}, {description!r}, {cloud_only!r}, ' \
               '{subscription_only!r}, {is_agent!r})'
        return form.format(**self.__dict__)

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusTemplate':
        uuid = str(json_dict['uuid'])
        name = str(json_dict['name'])
        title = str(json_dict['title'])
        description = str(json_dict['description'])
        cloud_only = bool(json_dict['cloud_only'])
        subscription_only = bool(json_dict['subscription_only'])
        is_agent = bool(json_dict['is_agent'])

        return NessusTemplate(uuid, name, title, description, cloud_only, subscription_only, is_agent)
