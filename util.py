import copy

def default(dct, key, default=None):
    try:
        return dct[key]
    except KeyError:
        return copy.deepcopy(default)