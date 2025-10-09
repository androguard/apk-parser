import json
import os
import re
from typing import Union

from apkparser.helper.logging import LOGGER


class InvalidResourceError(Exception):
    pass

class APILevelNotFoundError(Exception):
    pass


def load_api_specific_resource_module(
    resource_name: str, api: Union[str, int, None] = None, default_api: int = 16
) -> dict:
    """
    Load the module from the JSON files and return a dict, which might be empty
    if the resource could not be loaded.

    If no api version is given, the default one from the CONF dict is used.

    :param resource_name: Name of the resource to load
    :param api: API version
    :param default_api: Default API version
    :raises InvalidResourceError: if resource not found
    :returns: dict
    """
    loader = dict(
        aosp_permissions=load_permissions,
        api_permission_mappings=load_permission_mappings,
    )

    if resource_name not in loader:
        raise InvalidResourceError(
            "Invalid Resource '{}', not in [{}]".format(
                resource_name, ", ".join(loader.keys())
            )
        )

    if not api:
        api = default_api

    ret = loader[resource_name](api)

    if ret == {}:
        # No API mapping found, return default
        LOGGER.warning(
            "API mapping for API level {} was not found! "
            "Returning default, which is API level {}".format(
                api, CONF['DEFAULT_API']
            )
        )
        ret = loader[resource_name](default_api)

    return ret

def load_permissions(
    apilevel: Union[str, int], permtype: str = 'permissions'
) -> dict[str, dict[str, str]]:
    """
    Load the Permissions for the given apilevel.

    The permissions lists are generated using this tool: https://github.com/U039b/aosp_permissions_extraction

    Has a fallback to select the maximum or minimal available API level.
    For example, if 28 is requested but only 26 is available, 26 is returned.
    If 5 is requested but 16 is available, 16 is returned.

    If an API level is requested which is in between of two API levels we got,
    the lower level is returned. For example, if 5,6,7,10 is available and 8 is
    requested, 7 is returned instead.

    :param apilevel:  integer value of the API level
    :param permtype: either load permissions (`'permissions'`) or
    permission groups (`'groups'`)
    :return: a dictionary of {Permission Name: {Permission info}
    """
    if permtype not in ['permissions', 'groups']:
        raise ValueError("The type of permission list is not known.")

    # Usually apilevel is supplied as string...
    apilevel = int(apilevel)

    root = os.path.dirname(os.path.realpath(__file__))
    permissions_file = os.path.join(
        root, "aosp_permissions", "permissions_{}.json".format(apilevel)
    )

    levels = filter(
        lambda x: re.match(r'^permissions_\d+\.json$', x),
        os.listdir(os.path.join(root, "aosp_permissions")),
    )
    levels = list(map(lambda x: int(x[:-5].split('_')[1]), levels))

    if not levels:
        LOGGER.error("No Permissions available, can not load!")
        return {}

    LOGGER.debug(
        "Available API levels: {}".format(", ".join(map(str, sorted(levels))))
    )

    if not os.path.isfile(permissions_file):
        if apilevel > max(levels):
            LOGGER.warning(
                "Requested API level {} is larger than maximum we have, returning API level {} instead.".format(
                    apilevel, max(levels)
                )
            )
            return load_permissions(max(levels), permtype)
        if apilevel < min(levels):
            LOGGER.warning(
                "Requested API level {} is smaller than minimal we have, returning API level {} instead.".format(
                    apilevel, max(levels)
                )
            )
            return load_permissions(min(levels), permtype)

        # Missing level between existing ones, return the lower level
        lower_level = max(filter(lambda x: x < apilevel, levels))
        LOGGER.warning(
            "Requested API Level could not be found, using {} instead".format(
                lower_level
            )
        )
        return load_permissions(lower_level, permtype)

    with open(permissions_file, "r") as fp:
        return json.load(fp)[permtype]


def load_permission_mappings(
    apilevel: Union[str, int]
) -> dict[str, list[str]]:
    """
    Load the API/Permission mapping for the requested API level.
    If the requetsed level was not found, None is returned.

    :param apilevel: integer value of the API level, i.e. 24 for Android 7.0
    :return: a dictionary of {MethodSignature: [List of Permissions]}
    """
    root = os.path.dirname(os.path.realpath(__file__))
    permissions_file = os.path.join(
        root, "api_permission_mappings", "permissions_{}.json".format(apilevel)
    )

    if not os.path.isfile(permissions_file):
        return {}

    with open(permissions_file, "r") as fp:
        return json.load(fp)
