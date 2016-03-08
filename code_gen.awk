#!/usr/bin/awk -E

BEGIN {
	FS = "([\"{}]|[[:space:]]+)"

	init_head = "\tdef __init__(self, "

	repr_body = "\t\tform = '" classname "("

	json_tail = "\t\treturn " classname "("
}

/\s*["]/ {
	name = $3
	type = to_py_type($6)

	init_head = init_head name ": " type ", "

	init_body = init_body "\t\tself." name " = " name "\n"
	repr_body = repr_body "{" name "!r}, "
	json_body = json_body "\t\t" name " = " type "(json_dict['" name "'])\n"

	json_tail = json_tail name ", "
}

END {
	init_head = remove_last(init_head, 2) ") -> None:"
	repr_body = remove_last(repr_body, 2) ")'"

	repr_head = "\tdef __repr__(self) -> str:"

	json_head = "\t@staticmethod\n\tdef from_json(json_dict: Mapping[str, Union[int, str, bool]]) -> '" classname "':"

	repr_tail = "\t\treturn form.format(**self.__dict__)\n"
	json_tail = substr(json_tail, 0, length(json_tail) - 2) ")"

	print "class " classname ":"

	print init_head
	print init_body

	print repr_head
	print repr_body
	print repr_tail

	print json_head
	print json_body
	print json_tail
}

function remove_last(str, num) {
	return substr(str, 0, length(str) - num)
}

function to_py_type(nessus_type) {
	switch(nessus_type) {
		case "boolean":
			return "bool"
		case "integer":
			return "int"
		case "string":
			return "str"
	}
}
