"""
sub modules for everything about the scans
"""

from enum import Enum
from uuid import uuid4

from typing import Iterable, Mapping, Union, Optional

from nessus.base import LibNessusBase
from nessus.editor import NessusTemplate
from nessus.model import lying_exist, lying_type, Object, lying_exist_and_type, allow_to_exist
from nessus.permissions import NessusPermission
from nessus.policies import NessusPolicy


class NessusScanType(Enum):
    """
    type of scan
    """
    local = 'local'
    remote = 'remote'
    agent = 'agent'


class NessusScanStatus(Enum):
    """
    current status of scan
    lies:
     - `empty` was added because sometimes, nessus return it (but it is not documented)
     - `canceled` is returned instead of `cancelled`
     - `processing` was added because sometimes, nessus return it (but it is not documented)
    """
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

    empty = 'empty'
    canceled = 'canceled'
    processing = 'processing'


class NessusScan(Object):
    """
    nessus is lying with:
     - `type` which is none but should be NessusScanType (str)
     - `status` which can be 'empty' but should be one of NessusScanStatus
     - `use_dashboard` which do not always exists
    """

    def __init__(self, scan_id: int, uuid: str, name: str, type: NessusScanType, owner: str, enabled: bool,
                 folder_id: int,
                 read: bool, status: NessusScanStatus, shared: bool, user_permissions: int, creation_date: int,
                 last_modification_date: int, control: bool, starttime: str, timezone: str, rrules: str,
                 use_dashboard: bool) -> None:
        self.id = scan_id
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

    def __eq__(self, other):
        return isinstance(other, NessusScan) and self.id == other.id

    def __hash__(self):
        return hash(self.id)

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScan':
        scan_id = int(json_dict['id'])
        uuid = str(json_dict['uuid'])
        name = str(json_dict['name'])
        scan_type = lying_type(json_dict['type'], NessusScanType)
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

        return NessusScan(scan_id, uuid, name, scan_type, owner, enabled, folder_id, read, status, shared,
                          user_permissions,
                          creation_date, last_modification_date, control, starttime, timezone, rrules, use_dashboard)


class NessusScanCreated(Object):
    """
    lies:
     - `notification_filter_type` does not always exist
     - `tag_id` does not always exist
    """

    def __init__(self, creation_date: int, custom_targets: str, default_permisssions: int, description: str,
                 emails: str, scan_id: int, last_modification_date: int, name: str, notification_filter_type: str,
                 notification_filters: str, owner: str, owner_id: int, policy_id: int, enabled: bool, rrules: str,
                 scanner_id: int, shared: int, starttime: str, tag_id: int, timezone: str, scan_type: str,
                 user_permissions: int, uuid: str, use_dashboard: bool) -> None:
        self.creation_date = creation_date
        self.custom_targets = custom_targets
        self.default_permisssions = default_permisssions
        self.description = description
        self.emails = emails
        self.id = scan_id
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
        self.type = scan_type
        self.user_permissions = user_permissions
        self.uuid = uuid
        self.use_dashboard = use_dashboard

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
        scan_type = str(json_dict['type'])
        user_permissions = int(json_dict['user_permissions'])
        uuid = str(json_dict['uuid'])
        use_dashboard = bool(json_dict['use_dashboard'])

        return NessusScanCreated(creation_date, custom_targets, default_permisssions, description, emails, scan_id,
                                 last_modification_date, name, notification_filter_type, notification_filters, owner,
                                 owner_id, policy_id, enabled, rrules, scanner_id, shared, starttime, tag_id, timezone,
                                 scan_type, user_permissions, uuid, use_dashboard)


class NessusScanDetailsInfo(Object):
    """
    lies:
     - `edit_allowed` is not always existing
     - `policy` is not always existing
     - `pci_can_upload` is not always existing
     - `hasaudittrail` is not always existing
     - `folder_id` is sometimes None
     - `targets` is not always existing
     - `timestamp` is not always existing
     - `haskb` is not always existing
     - `uuid` is not always existing
     - `hostcount` is not always existing
     - `scan_end` is not always existing
    """

    def __init__(self, acls: Iterable[NessusPermission], edit_allowed: bool, status: str, policy: str,
                 pci_can_upload: bool, hasaudittrail: bool,
                 scan_start: str, folder_id: int, targets: str, timestamp: int, object_id: int, scanner_name: str,
                 haskb: bool, uuid: str, hostcount: int, scan_end: str, name: str, user_permissions: int,
                 control: bool) -> None:
        self.acls = acls
        self.edit_allowed = edit_allowed
        self.status = status
        self.policy = policy
        self.pci_can_upload = pci_can_upload
        self.hasaudittrail = hasaudittrail
        self.scan_start = scan_start
        self.folder_id = folder_id
        self.targets = targets
        self.timestamp = timestamp
        self.object_id = object_id
        self.scanner_name = scanner_name
        self.haskb = haskb
        self.uuid = uuid
        self.hostcount = hostcount
        self.scan_end = scan_end
        self.name = name
        self.user_permissions = user_permissions
        self.control = control

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanDetailsInfo':
        acls = {NessusPermission.from_json(acl) for acl in json_dict['acls']}
        edit_allowed = lying_exist(json_dict, 'edit_allowed', bool)
        status = str(json_dict['status'])
        policy = lying_exist(json_dict, 'policy', str)
        pci_can_upload = lying_exist(json_dict, 'pci-can-upload', bool)
        hasaudittrail = lying_exist(json_dict, 'hasaudittrail', bool)
        scan_start = str(json_dict['scan_start'])
        folder_id = lying_type(json_dict['folder_id'], int)  # it's None actually
        targets = lying_exist(json_dict, 'targets', str)
        timestamp = lying_exist(json_dict, 'timestamp', int)
        object_id = int(json_dict['object_id'])
        scanner_name = str(json_dict['scanner_name'])
        haskb = lying_exist(json_dict, 'haskb', bool)
        uuid = lying_exist(json_dict, 'uuid', str)
        hostcount = lying_exist(json_dict, 'hostcount', int)
        scan_end = lying_exist(json_dict, 'scan_end', str)
        name = str(json_dict['name'])
        user_permissions = int(json_dict['user_permissions'])
        control = bool(json_dict['control'])

        return NessusScanDetailsInfo(acls, edit_allowed, status, policy, pci_can_upload, hasaudittrail, scan_start,
                                     folder_id, targets, timestamp, object_id, scanner_name, haskb, uuid, hostcount,
                                     scan_end, name, user_permissions, control)


class NessusScanHost(Object):
    """
    lies:
     - `hostname` can be str
    """

    def __init__(self, host_id: int, host_index: str, hostname: int, progress: str, critical: int, high: int,
                 medium: int, low: int, info: int, totalchecksconsidered: int, numchecksconsidered: int,
                 scanprogresstotal: int, scanprogresscurrent: int, score: int) -> None:
        self.host_id = host_id
        self.host_index = host_index
        self.hostname = hostname
        self.progress = progress
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
        self.info = info
        self.totalchecksconsidered = totalchecksconsidered
        self.numchecksconsidered = numchecksconsidered
        self.scanprogresstotal = scanprogresstotal
        self.scanprogresscurrent = scanprogresscurrent
        self.score = score

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanHost':
        host_id = int(json_dict['host_id'])
        host_index = str(json_dict['host_index'])
        hostname = lying_type(json_dict['hostname'], int, str)
        progress = str(json_dict['progress'])
        critical = int(json_dict['critical'])
        high = int(json_dict['high'])
        medium = int(json_dict['medium'])
        low = int(json_dict['low'])
        info = int(json_dict['info'])
        totalchecksconsidered = int(json_dict['totalchecksconsidered'])
        numchecksconsidered = int(json_dict['numchecksconsidered'])
        scanprogresstotal = int(json_dict['scanprogresstotal'])
        scanprogresscurrent = int(json_dict['scanprogresscurrent'])
        score = int(json_dict['score'])

        return NessusScanHost(host_id, host_index, hostname, progress, critical, high, medium, low, info,
                              totalchecksconsidered, numchecksconsidered, scanprogresstotal, scanprogresscurrent,
                              score)


class NessusScanNote(Object):
    def __init__(self, title: str, message: str, severity: int) -> None:
        self.title = title
        self.message = message
        self.severity = severity

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanNote':
        title = str(json_dict['title'])
        message = str(json_dict['message'])
        severity = int(json_dict['severity'])

        return NessusScanNote(title, message, severity)


class NessusScanRemediation(Object):
    def __init__(self, value: str, remediation: str, hosts: int, vulns: int) -> None:
        self.value = value
        self.remediation = remediation
        self.hosts = hosts
        self.vulns = vulns

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanRemediation':
        value = str(json_dict['value'])
        remediation = str(json_dict['remediation'])
        hosts = int(json_dict['hosts'])
        vulns = int(json_dict['vulns'])

        return NessusScanRemediation(value, remediation, hosts, vulns)


class NessusScanDetailsRemediations(Object):
    """
    lies:
     - `remediations` can be None
    """

    def __init__(self, remediations: Iterable[NessusScanRemediation], num_hosts: int, num_cves: int,
                 num_impacted_hosts: int, num_remediated_cves: int) -> None:
        self.remediations = remediations
        self.num_hosts = num_hosts
        self.num_cves = num_cves
        self.num_impacted_hosts = num_impacted_hosts
        self.num_remediated_cves = num_remediated_cves

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanDetailsRemediations':
        remediations = {NessusScanRemediation(remediation) for remediation in
                        lying_type(json_dict['remediations'], list, lambda x: None, list())}
        num_hosts = int(json_dict['num_hosts'])
        num_cves = int(json_dict['num_cves'])
        num_impacted_hosts = int(json_dict['num_impacted_hosts'])
        num_remediated_cves = int(json_dict['num_remediated_cves'])

        return NessusScanDetailsRemediations(remediations, num_hosts, num_cves, num_impacted_hosts,
                                             num_remediated_cves)


class NessusScanVulnerability(Object):
    def __init__(self, plugin_id: int, plugin_name: str, plugin_family: str, count: int, vuln_index: int,
                 severity_index: int) -> None:
        self.plugin_id = plugin_id
        self.plugin_name = plugin_name
        self.plugin_family = plugin_family
        self.count = count
        self.vuln_index = vuln_index
        self.severity_index = severity_index

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanVulnerability':
        plugin_id = int(json_dict['plugin_id'])
        plugin_name = str(json_dict['plugin_name'])
        plugin_family = str(json_dict['plugin_family'])
        count = int(json_dict['count'])
        vuln_index = int(json_dict['vuln_index'])
        severity_index = int(json_dict['severity_index'])

        return NessusScanVulnerability(plugin_id, plugin_name, plugin_family, count, vuln_index, severity_index)


class NessusScanHistory(Object):
    def __init__(self, history_id: int, uuid: str, owner_id: int, status: str, creation_date: int,
                 last_modification_date: int) -> None:
        self.history_id = history_id
        self.uuid = uuid
        self.owner_id = owner_id
        self.status = status
        self.creation_date = creation_date
        self.last_modification_date = last_modification_date

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanHistory':
        history_id = int(json_dict['history_id'])
        uuid = str(json_dict['uuid'])
        owner_id = int(json_dict['owner_id'])
        status = str(json_dict['status'])
        creation_date = int(json_dict['creation_date'])
        last_modification_date = int(json_dict['last_modification_date'])

        return NessusScanHistory(history_id, uuid, owner_id, status, creation_date, last_modification_date)


class NessusScanFilterControl(Object):
    """
    lies:
     - `readable_regest` is not always there
     - `regex` is not always there
     - `options` is not always there
    """

    # FIXME what is the type of `options`?
    def __init__(self, type: str, readable_regest: str, regex: str, options: Iterable) -> None:
        self.type = type
        self.readable_regest = readable_regest
        self.regex = regex
        self.options = options

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanFilterControl':
        type = str(json_dict['type'])
        readable_regest = lying_exist(json_dict, 'readable_regest', str)
        regex = lying_exist(json_dict, 'regex', str)
        options = lying_exist(json_dict, 'options', str)

        return NessusScanFilterControl(type, readable_regest, regex, options)


class NessusScanFilterOperator(Enum):
    eq = 'eq'
    neq = 'neq'
    lt = 'lt'
    gt = 'gt'
    match = 'match'
    nmatch = 'nmatch'
    date_eq = 'date-eq'
    date_neq = 'date-neq'
    date_lt = 'date-lt'
    date_gt = 'date-gt'


class NessusScanFilter(Object):
    def __init__(self, name: str, readable_name: str, operators: Iterable[NessusScanFilterOperator],
                 control: NessusScanFilterControl) -> None:
        self.name = name
        self.readable_name = readable_name
        self.operators = operators
        self.control = control

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanFilter':
        name = str(json_dict['name'])
        readable_name = str(json_dict['readable_name'])
        operators = {NessusScanFilterOperator(operator) for operator in json_dict['operators']}
        control = NessusScanFilterControl.from_json(json_dict['control'])

        return NessusScanFilter(name, readable_name, operators, control)


class NessusScanDetails(Object):
    """
    we currently drop the `dashboard` field, is it needed?
    lies:
     - `hosts` not always existing
     - `comphosts` not always existing
     - `notes` not always existing
     - `notes` is sometimes None
     - `remediations` not always existing
     - `vulnerabilities` not always existing
     - `compliance` not always existing
     - `history` is sometimes None
     - `filters` not always existing
    """

    def __init__(self, info: NessusScanDetailsInfo, hosts: Iterable[NessusScanHost],
                 comphosts: Iterable[NessusScanHost], notes: Iterable[NessusScanNote],
                 remediations: NessusScanDetailsRemediations, vulnerabilites: Iterable[NessusScanVulnerability],
                 compliance: Iterable[NessusScanVulnerability], history: Iterable[NessusScanHistory],
                 filters: Iterable[NessusScanFilter]) -> None:
        self.info = info
        self.hosts = hosts
        self.comphosts = comphosts
        self.notes = notes
        self.remediations = remediations
        self.vulnerabilites = vulnerabilites
        self.compliance = compliance
        self.history = history
        self.filters = filters

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanDetails':
        info = NessusScanDetailsInfo.from_json(json_dict['info'])
        hosts = {NessusScanHost.from_json(host) for host in lying_exist(json_dict, 'hosts', list)}
        comphosts = {NessusScanHost.from_json(host) for host in lying_exist(json_dict, 'comphosts', list)}
        notes = {NessusScanNote.from_json(note) for note in
                 lying_exist_and_type(json_dict, 'notes', list, lambda x: list(), list())}
        remediations = lying_exist(json_dict, 'remediations', NessusScanDetailsRemediations.from_json, None)
        vulnerabilities = {NessusScanVulnerability.from_json(vulnerability) for vulnerability in
                           lying_exist(json_dict, 'vulnerabilities', list)}
        compliance = {NessusScanVulnerability.from_json(vulnerability) for vulnerability in
                      lying_exist(json_dict, 'compliance', list)}
        history = {NessusScanHistory.from_json(history) for history in
                   lying_type(json_dict['history'], list, lambda x: list())}
        filters = {NessusScanFilter.from_json(filtered) for filtered in lying_exist(json_dict, 'filters', list)}

        return NessusScanDetails(info, hosts, comphosts, notes, remediations, vulnerabilities, compliance, history,
                                 filters)


class NessusScanHostDetailsInfo(Object):
    """
    lies:
     - `host-fqdn` not always existing
    """

    def __init__(self, host_start: str, mac_address: str, host_fqdn: str, host_end: str, operating_system: str,
                 host_ip: str) -> None:
        self.host_start = host_start
        self.mac_address = mac_address
        self.host_fqdn = host_fqdn
        self.host_end = host_end
        self.operating_system = operating_system
        self.host_ip = host_ip

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanHostDetailsInfo':
        host_start = str(json_dict['host_start'])
        mac_address = str(json_dict['mac-address'])
        host_fqdn = lying_exist(json_dict, 'host-fqdn', str)
        host_end = str(json_dict['host_end'])
        operating_system = str(json_dict['operating-system'])
        host_ip = str(json_dict['host-ip'])

        return NessusScanHostDetailsInfo(host_start, mac_address, host_fqdn, host_end, operating_system, host_ip)


class NessusScanHostCompliance(Object):
    def __init__(self, host_id: int, hostname: str, plugin_id: int, plugin_name: str, plugin_family: str, count: int,
                 severity_index: int, severity: int) -> None:
        self.host_id = host_id
        self.hostname = hostname
        self.plugin_id = plugin_id
        self.plugin_name = plugin_name
        self.plugin_family = plugin_family
        self.count = count
        self.severity_index = severity_index
        self.severity = severity

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanHostCompliance':
        host_id = int(json_dict['host_id'])
        hostname = str(json_dict['hostname'])
        plugin_id = int(json_dict['plugin_id'])
        plugin_name = str(json_dict['plugin_name'])
        plugin_family = str(json_dict['plugin_family'])
        count = int(json_dict['count'])
        severity_index = int(json_dict['severity_index'])
        severity = int(json_dict['severity'])

        return NessusScanHostCompliance(host_id, hostname, plugin_id, plugin_name, plugin_family, count, severity_index,
                                        severity)


class NessusScanHostVulnerability(Object):
    def __init__(self, host_id: int, hostname: str, plugin_id: int, plugin_name: str, plugin_family: str, count: int,
                 vuln_index: int, severity_index: int, severity: int) -> None:
        self.host_id = host_id
        self.hostname = hostname
        self.plugin_id = plugin_id
        self.plugin_name = plugin_name
        self.plugin_family = plugin_family
        self.count = count
        self.vuln_index = vuln_index
        self.severity_index = severity_index
        self.severity = severity

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanHostVulnerability':
        host_id = int(json_dict['host_id'])
        hostname = str(json_dict['hostname'])
        plugin_id = int(json_dict['plugin_id'])
        plugin_name = str(json_dict['plugin_name'])
        plugin_family = str(json_dict['plugin_family'])
        count = int(json_dict['count'])
        vuln_index = int(json_dict['vuln_index'])
        severity_index = int(json_dict['severity_index'])
        severity = int(json_dict['severity'])

        return NessusScanHostVulnerability(host_id, hostname, plugin_id, plugin_name, plugin_family, count, vuln_index,
                                           severity_index, severity)


class NessusScanHostDetails(Object):
    def __init__(self, info: NessusScanHostDetailsInfo, compliance: Iterable[NessusScanHostCompliance],
                 vulnerabilities: Iterable[NessusScanHostVulnerability]) -> None:
        self.info = info
        self.compliance = compliance
        self.vulnerabilities = vulnerabilities

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanHostDetails':
        info = NessusScanHostDetailsInfo.from_json(json_dict['info'])
        compliance = {NessusScanHostCompliance.from_json(compliance) for compliance in json_dict['compliance']}
        vulnerabilities = {NessusScanHostVulnerability.from_json(vulnerability) for vulnerability in
                           json_dict['vulnerabilities']}

        return NessusScanHostDetails(info, compliance, vulnerabilities)


class NessusScanPluginOutputInfoDescriptionAttributesRiskInformation(Object):
    """
    lies:
     - there is more than simply risk_factor
      - `cvss_score`: str (but could be float, we use that)
      - `cvss_vector`: str
      - `cvss_temporal_score`: str (but could be float, we use that)
      - `cvss_temporal_vector`: str
    """

    def __init__(self, risk_factor: str, cvss_score: Optional[float], cvss_vector: Optional[str],
                 cvss_temporal_score: Optional[float], cvss_temporal_vector: Optional[str]) -> None:
        self.risk_factor = risk_factor
        self.cvss_score = cvss_score
        self.cvss_vector = cvss_vector
        self.cvss_temporal_score = cvss_temporal_score
        self.cvss_temporal_vector = cvss_temporal_vector

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) \
            -> 'NessusScanPluginOutputInfoDescriptionAttributesRiskInformation':
        risk_factor = str(json_dict['risk_factor'])
        cvss_score = allow_to_exist(json_dict, 'cvss_score', float)
        cvss_vector = allow_to_exist(json_dict, 'cvss_vector', str)
        cvss_temporal_score = allow_to_exist(json_dict, 'cvss_temporal_score', float)
        cvss_temporal_vector = allow_to_exist(json_dict, 'cvss_temporal_vector', str)

        return NessusScanPluginOutputInfoDescriptionAttributesRiskInformation(risk_factor, cvss_score, cvss_vector,
                                                                              cvss_temporal_score, cvss_temporal_vector)


class NessusScanPluginOutputInfoDescriptionAttributesPluginInformation(Object):
    def __init__(self, plugin_id: int, plugin_type: str, plugin_family: str, plugin_modification_date: str) -> None:
        self.plugin_id = plugin_id
        self.plugin_type = plugin_type
        self.plugin_family = plugin_family
        self.plugin_modification_date = plugin_modification_date

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) \
            -> 'NessusScanPluginOutputInfoDescriptionAttributesPluginInformation':
        plugin_id = int(json_dict['plugin_id'])
        plugin_type = str(json_dict['plugin_type'])
        plugin_family = str(json_dict['plugin_family'])
        plugin_modification_date = str(json_dict['plugin_modification_date'])

        return NessusScanPluginOutputInfoDescriptionAttributesPluginInformation(plugin_id, plugin_type, plugin_family,
                                                                                plugin_modification_date)


class NessusScanPluginOutputInfoDescriptionAttributes(Object):
    def __init__(self, risk_information: NessusScanPluginOutputInfoDescriptionAttributesRiskInformation,
                 plugin_name: str, plugin_information: NessusScanPluginOutputInfoDescriptionAttributesPluginInformation,
                 solution: str, fname: str, synopsis: str, description: str) -> None:
        self.risk_information = risk_information
        self.plugin_name = plugin_name
        self.plugin_information = plugin_information
        self.solution = solution
        self.fname = fname
        self.synopsis = synopsis
        self.description = description

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanPluginOutputInfoDescriptionAttributes':
        risk_information = \
            NessusScanPluginOutputInfoDescriptionAttributesRiskInformation.from_json(json_dict['risk_information'])
        plugin_name = str(json_dict['plugin_name'])
        plugin_information = \
            NessusScanPluginOutputInfoDescriptionAttributesPluginInformation.from_json(json_dict['plugin_information'])
        solution = str(json_dict['solution'])
        fname = str(json_dict['fname'])
        synopsis = str(json_dict['synopsis'])
        description = str(json_dict['description'])

        return NessusScanPluginOutputInfoDescriptionAttributes(risk_information, plugin_name, plugin_information,
                                                               solution, fname, synopsis, description)


class NessusScanPluginOutputInfoDescription(Object):
    def __init__(self, severity: int, pluginname: str,
                 pluginattributes: NessusScanPluginOutputInfoDescriptionAttributes, pluginfamily: str,
                 pluginid: int) -> None:
        self.severity = severity
        self.pluginname = pluginname
        self.pluginattributes = pluginattributes
        self.pluginfamily = pluginfamily
        self.pluginid = pluginid

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanPluginOutputInfoDescription':
        severity = int(json_dict['severity'])
        pluginname = str(json_dict['pluginname'])
        pluginattributes = NessusScanPluginOutputInfoDescriptionAttributes.from_json(json_dict['pluginattributes'])
        pluginfamily = str(json_dict['pluginfamily'])
        pluginid = int(json_dict['pluginid'])

        return NessusScanPluginOutputInfoDescription(severity, pluginname, pluginattributes, pluginfamily, pluginid)


class NessusScanPluginOutput(Object):
    def __init__(self, plugin_output: str, hosts: str, severity: int, ports) -> None:
        self.plugin_output = plugin_output
        self.hosts = hosts
        self.severity = severity
        self.ports = ports

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanPluginOutput':
        plugin_output = str(json_dict['plugin_output'])
        hosts = str(json_dict['hosts'])
        severity = int(json_dict['severity'])
        ports = (json_dict['ports'])
        print(ports)

        return NessusScanPluginOutput(plugin_output, hosts, severity, ports)


class NessusScanPluginOutputInfo(Object):
    def __init__(self, plugindescription: NessusScanPluginOutputInfoDescription) -> None:
        self.plugindescription = plugindescription

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanPluginOutputInfo':
        plugindescription = NessusScanPluginOutputInfoDescription.from_json(json_dict['plugindescription'])

        return NessusScanPluginOutputInfo(plugindescription)


class NessusScanPluginOutputDetails(Object):
    def __init__(self, info: NessusScanPluginOutputInfo, output: Iterable[NessusScanPluginOutput]) -> None:
        self.info = info
        self.output = output

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusScanPluginOutputDetails':
        info = NessusScanPluginOutputInfo.from_json(json_dict['info'])
        output = {NessusScanPluginOutput.from_json(output) for output in json_dict['output']}

        return NessusScanPluginOutputDetails(info, output)


class LibNessusScans(LibNessusBase):
    """
    module handling /scans
    """

    # pylint: disable=bad-whitespace
    def create(self, policy: NessusPolicy, name: Optional[str] = None, template: Optional[NessusTemplate] = None,
               default_targets: Iterable[str] = ('localhost',)) -> NessusScanCreated:
        """
        Creates a scan.
        :param policy: policy to use
        :param name: name you want for the scan
        :param template: template will be taken from policy if not given
        :param default_targets: need to have at least an element
        :return: created scan
        """
        if name is None:
            name = str(uuid4())

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

    def delete(self, scan: NessusScan) -> None:
        """
        Deletes a scan.
        Scans in running, paused or stopping states can not be deleted.
        :param scan: the soon-to-be-deleted
        """
        url = 'scans/{}'.format(scan.id)
        self._delete(url)

    def launch(self, scan: NessusScan, alt_targets: Optional[Iterable[str]] = None) -> str:
        """
        Launches a scan.
        :param scan: the soon-to-be-launch
        :param alt_targets: target to scan, if not given, default to the one set during scan creation
        :return: uuid of the launched scan
        """
        url = 'scans/{scan_id}/launch'.format(scan_id=scan.id)
        json = alt_targets and {'alt_targets': alt_targets}
        ans = self._post(url, json=json)
        return ans.json()['scan_uuid']

    def details(self, scan: NessusScan) -> NessusScanDetails:
        url = 'scans/{scan_id}'.format(scan_id=scan.id)
        ans = self._get(url)
        return NessusScanDetails.from_json(ans.json())

    def host_details(self, scan: NessusScan, host: NessusScanHost) -> NessusScanHostDetails:
        url = 'scans/{scan_id}/hosts/{host_id}'.format(scan_id=scan.id, host_id=host.host_id)
        ans = self._get(url)
        return NessusScanHostDetails.from_json(ans.json())

    def plugin_output(self, scan: NessusScan, host: NessusScanHost, plugin_id: int) -> NessusScanPluginOutputDetails:
        url = 'scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}'.format(scan_id=scan.id, host_id=host.host_id,
                                                                           plugin_id=plugin_id)
        ans = self._get(url)
        return NessusScanPluginOutputDetails.from_json(ans.json())
