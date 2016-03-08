from enum import Enum
from uuid import uuid4

from nessus.policies import NessusPolicy
from typing import Iterable, Mapping, Union, Optional

from nessus.base import LibNessusBase
from nessus.editor import NessusTemplate
from nessus.model import lying_exist, lying_type


class NessusScanType(Enum):
    local = 'local'
    remote = 'remote'
    agent = 'agent'


class NessusScanStatus(Enum):
    completed = 'completed'
    aborted = 'aborted'
    imported = 'imported'
    pending = 'pending'
    running = 'running'
    resuming = 'resuming'
    canceling = 'canceling'
    cancelled = 'cancelled'
    pausing = 'pausing'
    paused = 'paused'
    stopping = 'stopping'
    stopped = 'stopped'

    empty = 'empty'  # should not exist but nessus is lying


class NessusScan:
    """
    nessus is lying with:
     - `type` which is none but should be NessusScanType (str)
     - `status` which can be 'empty' but should be one of NessusScanStatus
    """

    def __init__(self, id: int, uuid: str, name: str, type: NessusScanType, owner: str, enabled: bool, folder_id: int,
                 read: bool, status: NessusScanStatus, shared: bool, user_permissions: int, creation_date: int,
                 last_modification_date: int, control: bool, starttime: str, timezone: str, rrules: str,
                 use_dashboard: bool) -> None:
        self.id = id
        self.uuid = uuid
        self.name = name
        self.type = type
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
        self.use_dashboard = use_dashboard

    def __repr__(self) -> str:
        form = 'NessusTemplate({id!r}, {uuid!r}, {name!r}, {type!r}, {owner!r}, {enabled!r}, {folder_id!r}, ' \
               '{read!r}, {status!r}, {shared!r}, {user_permissions!r}, {creation_date!r}, ' \
               '{last_modification_date!r}, {control!r}, {starttime!r}, {timezone!r}, {rrules!r}, {use_dashboard!r})'
        return form.format(**self.__dict__)

    def __eq__(self, other):
        return isinstance(other, NessusScan) and self.id == other.id

    def __hash__(self):
        return hash(self.id)

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScan':
        id = int(json_dict['id'])
        uuid = str(json_dict['uuid'])
        name = str(json_dict['name'])
        type = lying_type(json_dict['type'], NessusScanType, lambda x: x)  # it's None actually
        owner = str(json_dict['owner'])
        enabled = bool(json_dict['enabled'])
        folder_id = int(json_dict['folder_id'])
        read = bool(json_dict['read'])
        status = NessusScanStatus(json_dict['status'])
        shared = bool(json_dict['shared'])
        user_permissions = int(json_dict['user_permissions'])
        creation_date = int(json_dict['creation_date'])
        last_modification_date = int(json_dict['last_modification_date'])
        control = bool(json_dict['control'])
        starttime = str(json_dict['starttime'])
        timezone = str(json_dict['timezone'])
        rrules = str(json_dict['rrules'])
        use_dashboard = lying_exist(json_dict, 'use_dashboard', bool)

        return NessusScan(id, uuid, name, type, owner, enabled, folder_id, read, status, shared, user_permissions,
                          creation_date, last_modification_date, control, starttime, timezone, rrules, use_dashboard)


class NessusScanCreated:
    def __init__(self, creation_date: int, custom_targets: str, default_permisssions: int, description: str,
                 emails: str, id: int, last_modification_date: int, name: str, notification_filter_type: str,
                 notification_filters: str, owner: str, owner_id: int, policy_id: int, enabled: bool, rrules: str,
                 scanner_id: int, shared: int, starttime: str, tag_id: int, timezone: str, type: str,
                 user_permissions: int, uuid: str, use_dashboard: bool) -> None:
        self.creation_date = creation_date
        self.custom_targets = custom_targets
        self.default_permisssions = default_permisssions
        self.description = description
        self.emails = emails
        self.id = id
        self.last_modification_date = last_modification_date
        self.name = name
        self.notification_filter_type = notification_filter_type
        self.notification_filters = notification_filters
        self.owner = owner
        self.owner_id = owner_id
        self.policy_id = policy_id
        self.enabled = enabled
        self.rrules = rrules
        self.scanner_id = scanner_id
        self.shared = shared
        self.starttime = starttime
        self.tag_id = tag_id
        self.timezone = timezone
        self.type = type
        self.user_permissions = user_permissions
        self.uuid = uuid
        self.use_dashboard = use_dashboard

    def __repr__(self) -> str:
        form = 'NessusScanCreated({creation_date!r}, {custom_targets!r}, {default_permisssions!r}, {description!r}, ' \
               '{emails!r}, {id!r}, {last_modification_date!r}, {name!r}, {notification_filter_type!r}, ' \
               '{notification_filters!r}, {owner!r}, {owner_id!r}, {policy_id!r}, {enabled!r}, {rrules!r}, ' \
               '{scanner_id!r}, {shared!r}, {starttime!r}, {tag_id!r}, {timezone!r}, {type!r}, ' \
               '{user_permissions!r}, {uuid!r}, {use_dashboard!r})'
        return form.format(**self.__dict__)

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanCreated':
        creation_date = int(json_dict['creation_date'])
        custom_targets = str(json_dict['custom_targets'])
        default_permisssions = int(json_dict['default_permisssions'])
        description = str(json_dict['description'])
        emails = str(json_dict['emails'])
        scan_id = int(json_dict['id'])
        last_modification_date = int(json_dict['last_modification_date'])
        name = str(json_dict['name'])
        notification_filter_type = lying_exist(json_dict, 'notification_filter_type', str)
        notification_filters = str(json_dict['notification_filters'])
        owner = str(json_dict['owner'])
        owner_id = int(json_dict['owner_id'])
        policy_id = int(json_dict['policy_id'])
        enabled = bool(json_dict['enabled'])
        rrules = str(json_dict['rrules'])
        scanner_id = int(json_dict['scanner_id'])
        shared = int(json_dict['shared'])
        starttime = str(json_dict['starttime'])
        tag_id = lying_exist(json_dict, 'tag_id', int)
        timezone = str(json_dict['timezone'])
        type = str(json_dict['type'])
        user_permissions = int(json_dict['user_permissions'])
        uuid = str(json_dict['uuid'])
        use_dashboard = bool(json_dict['use_dashboard'])

        return NessusScanCreated(creation_date, custom_targets, default_permisssions, description, emails, scan_id,
                                 last_modification_date, name, notification_filter_type, notification_filters, owner,
                                 owner_id, policy_id, enabled, rrules, scanner_id, shared, starttime, tag_id, timezone,
                                 type, user_permissions, uuid, use_dashboard)


class LibNessusScans(LibNessusBase):
    def create(self, policy: NessusPolicy, name: str = str(uuid4()), template: Optional[NessusTemplate] = None,
               default_targets: Iterable[str] = list('localhost')) -> NessusScanCreated:
        """
        Creates a scan.
        :param policy: policy to use
        :param name: name you want for the scan
        :param template: template will be taken from policy if not given
        :param default_targets: need to have at least an element
        :return: created scan
        """

        if template is None:
            template_uuid = policy.template_uuid
        else:
            template_uuid = template.uuid

        json = {
            'uuid': template_uuid,
            'settings': {
                'name': name,
                'policy_id': policy.id,
                'enabled': False,
                'text_targets': ','.join(default_targets),
            },
        }

        ans = self._post('scans', json=json)

        return NessusScanCreated.from_json(ans.json()['scan'])

    def list(self) -> Iterable[NessusScan]:
        ans = self._get('scans')

        if ans.json()['scans'] is None:
            return set()

        return {NessusScan.from_json(elem) for elem in ans.json()['scans']}
