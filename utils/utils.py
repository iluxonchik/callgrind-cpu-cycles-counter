
def convert_dict_keys_to_str(orig_dict):
    if not isinstance(orig_dict, dict):
        return orig_dict
    dict_entries = ((str(key), convert_dict_keys_to_str(value))
                    for key, value in orig_dict.items())
    return dict(dict_entries)
