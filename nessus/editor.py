from enum import Enum

from typing import Mapping, Union, Iterable

from nessus.base import LibNessusBase
from nessus.model import lying_exist

class NessusTemplate:
    """
    nessus is lying with:
     - `description` which is not always there
    """

    def __init__(self, uuid: str, name: str, title: str, description: str, cloud_only: bool, subscription_only: bool,
                 is_agent: bool, more_info: str) -> None:
        self.uuid = uuid
        self.name = name
        self.title = title
        self.description = description
        self.cloud_only = cloud_only
        self.subscription_only = subscription_only
        self.is_agent = is_agent
        self.more_info = more_info

    def __repr__(self) -> str:
        form = 'NessusTemplate({uuid!r}, {name!r}, {title!r}, {description!r}, {cloud_only!r}, ' \
               '{subscription_only!r}, {is_agent!r}, {more_info!r})'
        return form.format(**self.__dict__)

    def __eq__(self, other):
        return isinstance(other, NessusTemplate) and self.uuid == other.uuid

    def __hash__(self):
        return hash(self.uuid)

    @staticmethod
    def from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> 'NessusTemplate':
        uuid = str(json_dict['uuid'])
        name = str(json_dict['name'])
        title = str(json_dict['title'])
        description = lying_exist(json_dict, 'description', str)
        cloud_only = bool(json_dict['cloud_only'])
        subscription_only = bool(json_dict['subscription_only'])
        is_agent = bool(json_dict['is_agent'])
        more_info = lying_exist(json_dict, 'more_info', str)

        return NessusTemplate(uuid, name, title, description, cloud_only, subscription_only, is_agent, more_info)


class NessusTemplateType(Enum):
    scan = 'scan'
    policy = 'policy'


class LibNessusEditor(LibNessusBase):
    def list(self, template_type: NessusTemplateType) -> Iterable[NessusTemplate]:
        url = 'editor/{type}/templates'.format(type=template_type.value)
        ans = self._get(url)

        return {NessusTemplate.from_json(t) for t in ans.json()['templates']}
