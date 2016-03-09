"""
dear Nessus dev, if you want to see where there is issues with your REST API, please modify `lying_type` and
`lying_exist` to become NOP
"""
import functools

from typing import TypeVar, Mapping, Union, Callable, Any, Optional

T = TypeVar('T')
U = TypeVar('U')
V = TypeVar('V')

JsonType = Union[int, str, bool]


class Object:
    def __repr__(self) -> str:
        """
        more magic, we want a generic way to repr a model, so we take the current values of self and the args to the
        init function and try to match them together
        :return: repr of the model
        """
        classname = self.__class__.__name__
        init = getattr(self, '__init__')
        args = init.__code__.co_varnames[1:]
        args_str = ['{{{}!r}}'.format(a) for a in args]

        ret = '{classname}({args})'.format(classname=classname, args=', '.join(args_str))

        values = dict()
        for k, v in self.__dict__.items():
            if k in args:
                real_key = k
            else:
                real_key = next(arg for arg in args if arg.endswith(k))
            values[real_key] = v

        return ret.format(**values)


def lying_type(value: U, excepted_type: Callable[[U], Any], actual_type: Callable[[U], T] = lambda x: x,
               default: V = ...) -> Union[T,Any]:
    """
    document that we excepted the given type for the given value, but it was not the case
    a NOP would be `return excepted_type(value)`
    :param value: value we got
    :param excepted_type: type we excepted
    :param actual_type: real type we got
    :return: type we got
    """
    if default is not ...:
        return default
    return actual_type(value)


def __default_if_args(if_no_arg: Callable[[], T], if_arg: Callable[[Any], T], *args) -> T:
    """
    if it was given one arg, call `if_arg` with it, if got no arg, call `if_no_arg`
    :param if_no_arg: to call if no arg
    :param if_arg: to call if arg
    :param args: passed to `if_arg`
    :return: result from either `if_no_arg` or `if_arg`
    """
    assert len(args) in (0, 1)
    if args:
        return if_arg(*args)
    return if_no_arg()


def lying_exist_and_type(json_dict: Mapping[str, JsonType], excepted_name: str, excepted_type: Callable[[Any], T],
                         actual_type: Callable[[Any], U], default: Optional[U] = None) -> U:
    if excepted_name in json_dict:
        return actual_type(json_dict[excepted_name])
    else:
        return default


def lying_exist(json_dict: Mapping[str, JsonType], excepted_name: str, excepted_type: Callable[[Any], T],
                default: U = ...) -> Union[T, U]:
    """
    document that we excepted the given key, but it was not the case
    a NOP would be `return excepted_type(json_dict[excepted_name])`
    :param json_dict: where to look for the value
    :param excepted_name: key we excepted to find
    :param excepted_type: type of the value we excepted to find
    :param default: optional default value to return (we also use a bit of magic (`...`) to be able to pass None)
    :return: either the value if existing or the default
    """

    # we use this magic to be able to pass either `int` as `excepted_type` (which can take (0, 1) arg or one of our
    # `model.from_json` which have to have a single arg
    if default is not ...:
        to_call = functools.partial(__default_if_args, lambda: default, excepted_type)
    else:
        to_call = excepted_type

    if excepted_name in json_dict:
        return to_call(json_dict[excepted_name])
    else:
        return to_call()
