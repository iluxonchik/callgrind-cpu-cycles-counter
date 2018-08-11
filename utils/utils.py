import ast
import json

def convert_dict_keys_to_str(orig_dict):
    if not isinstance(orig_dict, dict):
        return orig_dict
    dict_entries = ((str(key), convert_dict_keys_to_str(value))
                    for key, value in orig_dict.items())
    return dict(dict_entries)

def parse_json_to_internal_dict(dictionary):
    def convert_to_literal(value):
        try:
            return ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return value

    if not isinstance(dictionary, dict):
        return dictionary

    dict_entries = ((convert_to_literal(key), parse_json_to_internal_dict(value))
                     for key, value in dictionary.items())
    return dict(dict_entries)


def parse_json_file_to_dict(path):
    """
    Convert JSON file into a project-specific representation of the data
    internally.

    NOTE: it's not the most Pythonic or elegant code you will find. It was
    written "just to work".
    """
    with open(path, 'r') as json_file:
        json_contents = json.load(json_file, object_hook=parse_json_to_internal_dict)
    return json_contents
