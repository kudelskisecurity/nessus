#!/usr/bin/env python3
import sys

from bs4 import BeautifulSoup
from typing import Iterable, Optional


class Object:
    def __repr__(self) -> str:
        classname = self.__class__.__name__
        init = getattr(self, '__init__')
        args = init.__code__.co_varnames[1:]
        args_str = ['{{{}!r}}'.format(a) for a in args]

        ret = '{classname}({args})'.format(classname=classname, args=', '.join(args_str))

        return ret.format(**self.__dict__)


class Parameter(Object):
    def __init__(self, name: str, param_type: type, description: str, required: bool) -> None:
        self.name = name
        self.param_type = param_type
        self.description = description
        self.required = required


class PathParameter(Parameter):
    pass


class BodyParameter(Parameter):
    pass


class RESTMethod(Object):
    def __init__(self, method: str, path: str, path_params: Optional[Iterable[PathParameter]],
                 body_params: Optional[Iterable[BodyParameter]]) -> None:
        self.method = method
        self.path = path
        self.path_params = path_params
        self.body_params = body_params


def json_type_to_python_type(json_type: str) -> type:
    ret = {
        'integer': int,
        'array': list,
        'string': str,
        'boolean': bool,
    }

    return ret[json_type]


def request() -> RESTMethod:
    request = main.find(lambda f: 'request' in f.get('class', []))
    http_request = request.find(lambda f: 'http-request' in f.get('class', []))
    splited_request = http_request.text.split()
    method, path = splited_request[0], splited_request[1][1:]

    tbody = request.table.tbody
    param_type = None
    params = {
        PathParameter: None,
        BodyParameter: None
    }
    for tr in tbody.find_all('tr'):
        if 'spanning' in tr.td.get('class'):
            category = tr.td.text
            if category == 'Path Parameters':
                param_type = PathParameter
            elif category == 'Request Payload':
                param_type = BodyParameter
            else:
                raise KeyError()
            params[param_type] = set()
        else:
            arg = [td.text for td in tr.find_all('td')]
            arg[1] = json_type_to_python_type(arg[1])
            arg[2] = arg[2].translate(str.maketrans({'\n': None}))
            arg[3] = bool(arg[3])
            param = param_type(*arg)
            params[param_type].add(param)
    return RESTMethod(method, path, params[PathParameter], params[BodyParameter])


def response():
    response = main.find(lambda f: f.get('class') == 'response')


soup = BeautifulSoup(sys.stdin.read(), 'html.parser')
main = soup.find(lambda f: f.get('id') == 'main')

req = request()
res = response()
