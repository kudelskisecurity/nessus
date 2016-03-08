from enum import Enum

from typing import Iterable, Mapping, Union

from nessus.base import LibNessusBase


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


class NessusScan:
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
        type = NessusScanType(json_dict['type'])
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
        use_dashboard = bool(json_dict['use_dashboard'])

        return NessusScan(id, uuid, name, type, owner, enabled, folder_id, read, status, shared, user_permissions,
                          creation_date, last_modification_date, control, starttime, timezone, rrules, use_dashboard)


class LibNessusScans(LibNessusBase):
    def list(self) -> Iterable[NessusScan]:
        ans = self._get('scans')

        if ans.json()['scans'] is None:
            return set()

        return {NessusScan.from_json(elem) for elem in ans.json()['scans']}
