from enum import Enum

from typing import Mapping, Union, Iterable

from nessus.base import LibNessusBase


class NessusTemplate:
    """
    nessus is lying with:
     - `description` which is not always there
    """
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
        cloud_only = bool(json_dict['cloud_only'])
        subscription_only = bool(json_dict['subscription_only'])
        is_agent = bool(json_dict['is_agent'])

        if 'description' in json_dict:
            description = str(json_dict['description'])
        else:
            description = None

        return NessusTemplate(uuid, name, title, description, cloud_only, subscription_only, is_agent)


class NessusTemplateType(Enum):
    scan = 'scan'
    policy = 'policy'


class LibNessusEditor(LibNessusBase):
    def list(self, template_type: NessusTemplateType) -> Iterable[NessusTemplate]:
        url = 'editor/{type}/templates'.format(type=template_type.value)
        ans = self._get(url)

        return {NessusTemplate.from_json(t) for t in ans.json()['templates']}
