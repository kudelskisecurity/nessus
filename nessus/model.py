from typing import TypeVar, Mapping, Union, Callable, Any, Optional

T = TypeVar('T')
U = TypeVar('U')

JsonType = Union[int, str, bool]


def lying_type(value: U, excepted_type: Callable[[U], Any], actual_type: Callable[[U], T]) -> T:
    return actual_type(value)


def lying_exist(json_dict: Mapping[str, JsonType], excepted_name: str,
                excepted_type: Callable[[Any], T]) -> Optional[T]:
    if excepted_name in json_dict:
        return excepted_type(json_dict[excepted_name])
    else:
        return None
