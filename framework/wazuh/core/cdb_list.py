# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import uuid
from os import listdir, chmod, remove
from os.path import isfile, isdir, join

from wazuh.core import common
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core.utils import find_nth, delete_wazuh_file

REQUIRED_FIELDS = ['relative_dirname', 'filename']
SORT_FIELDS = ['relative_dirname', 'filename']
CDB_EXTENSION = '.cdb'

_regex_path = r'^(etc/lists/)[\w\.\-/]+$'
_pattern_path = re.compile(_regex_path)


def get_relative_path(path):
    """Get relative path

    :param path: Original path
    :return: Relative path (from Wazuh base directory)
    """
    return path.replace(common.ossec_path, '')[1:]


def check_path(path):
    """Check if path is well formed (without './' or '../')

    :param path: Path to check
    :return: Result of check the path (boolean)
    """
    if './' in path or '../' in path or not _pattern_path.match(path):
        raise WazuhError(1801)


@common.context_cached('system_lists')
def iterate_lists(absolute_path=common.lists_path, only_names=False):
    """Get the content of all CDB lists

    :param absolute_path: Full path of directory to get CDB lists
    :param only_names: If this parameter is true, only the name of all lists will be showed
    :return: List with all CDB lists
    """
    dir_content = listdir(absolute_path)
    output = list()

    # For skipping .swp files
    regex_swp = r'^\.{1}[\w\-/]+(.swp){1}$'
    pattern = re.compile(regex_swp)

    for name in dir_content:
        new_absolute_path = join(absolute_path, name)
        new_relative_path = get_relative_path(new_absolute_path)
        # '.cdb' and '.swp' files are skipped
        if (isfile(new_absolute_path)) and ('.cdb' not in name) and ('~' not in name) and not pattern.search(name):
            if only_names:
                relative_path = get_relative_path(absolute_path)
                output.append({'relative_dirname': relative_path, 'filename': name})
            else:
                items = get_list_from_file(join(common.ossec_path, new_relative_path))
                output.append({'relative_dirname': new_relative_path, 'filename': name, 'items': items})
        elif isdir(new_absolute_path):
            output += iterate_lists(new_absolute_path, only_names=only_names)

    return output


def split_key_value_with_quotes(line, file_path='/CDB_LISTS_PATH'):
    """Return the key and value of a cdb list line when they are surrounded by quotes.

    Parameters
    ----------
    line : str
        String to split in key and value.
    file_path : str
        Relative path of list file which contains "line"

    Returns
    -------
    str
        Key of the CDB list line.
    str
        Value of the CDB list line.

    Raises
    ------
    WazuhError
        If the input line has a wrong format.
    """
    first_quote = find_nth(line, '"', 1)
    second_quote = find_nth(line, '"', 2)

    # Check if key AND value are surrounded by double quotes
    if line.count('"') == 4:
        third_quote = find_nth(line, '"', 3)
        fourth_quote = find_nth(line, '"', 4)

        key = line[first_quote + 1: second_quote]
        value = line[third_quote + 1: fourth_quote]

        # Check that the line starts with "...
        # Check that the line has the structure ...":"...
        # Check that the line finishes with ..."
        if first_quote != 0 or line[second_quote: third_quote + 1] != '":"' or fourth_quote != len(
                line) - 1:
            raise WazuhError(1800, extra_message={'path': join('WAZUH_HOME', file_path)})

    # Check whether the string surrounded by quotes is the key or the value
    elif line.count('"') == 2:
        # Check if the key is surrounded by quotes
        if line.find(":") > first_quote:
            key = line[first_quote + 1: second_quote]
            value = line[second_quote + 2:]

            # Check that the line starts with "...
            # Check that the line has the structure ...":...
            if first_quote != 0 or line[second_quote: second_quote + 2] != '":':
                raise WazuhError(1800, extra_message={'path': join('WAZUH_HOME', file_path)})

        # Check if the value is surrounded by quotes
        if line.find(":") < first_quote:
            key = line[: line.find(":")]
            value = line[first_quote + 1: second_quote]

            # Check that the line finishes with ..."
            # Check that the line has the structure ...:"...
            if second_quote != len(line) - 1 or line[first_quote - 1: first_quote + 1] != ':"':
                raise WazuhError(1800, extra_message={'path': join('WAZUH_HOME', file_path)})

    # There is an odd number of quotes (or more than 4)
    else:
        raise WazuhError(1800, extra_message={'path': join('WAZUH_HOME', file_path)})

    return key, value


def get_list_from_file(path, raw=False):
    """Get CDB list from a file.

    Parameters
    ----------
    path : string
        Full path of list file to get.
    raw : bool, optional
        Respond in raw format.

    Returns
    -------
    result : dict, str
        CDB list.
    """
    result = dict()

    try:
        with open(path) as f:
            output = f.read()

        if raw:
            result = output
        else:
            for line in output.splitlines():
                if 'TEMPLATE' not in line:
                    if '"' not in line:
                        # Check if key and value are not surrounded by double quotes
                        key, value = line.split(':')
                    else:
                        # Check if key and/or value are surrounded by double quotes
                        key, value = split_key_value_with_quotes(line, path)
                    result.update({key: value})

    except OSError as e:
        if e.errno == 2:
            raise WazuhError(1802)
        elif e.errno == 13:
            raise WazuhError(1803)
        elif e.errno == 21:
            raise WazuhError(1804, extra_message="{0} {1}".format(path, "is a directory"))
        else:
            raise e
    except ValueError:
        raise WazuhError(1800, extra_message={'path': path})

    return result


def validate_cdb_list(path):
    """Validate a CDB list.

    Parameters
    ----------
    path : str
        Full path of the file to validate.

    Returns
    -------
    bool
        True if CDB list is OK, False otherwise
    """
    # This regex allow any line like key:value.
    # If key or value contains ":", the whole key or value must be within quotes:
    # - test_key:test_value     VALID
    # - "test:key":test_value   VALID
    # - "test:key":"test:value" VALID
    # - "test:key":test:value   INVALID
    # - test:key:test_value     INVALID
    regex_cdb = re.compile(r'(?:^"([\w\-:]*?)"|^[^:"\'\s]+):(?:"([\w\-:]*?)"$|[^:]*$)')

    try:
        with open(path) as f:
            for line in f:
                # Skip empty lines
                if not line.strip():
                    continue
                if not re.match(regex_cdb, line):
                    return False
    except IOError:
        raise WazuhInternalError(1005)

    return True


def create_tmp_list(content):
    """Create temporal CDB list file and validate its content.

    Parameters
    ----------
    content : str
        Content of file to be created.

    Returns
    -------
    tmp_file_path : str
        Path to tmp file.
    """
    if len(content) == 0:
        raise WazuhError(1112)

    # Temporal file that will be moved to the final destination.
    tmp_file_path = f'{common.ossec_path}/tmp/api_tmp_file_{uuid.uuid4()}.txt'
    try:
        with open(tmp_file_path, 'w') as tmp_file:
            for element in content.splitlines():
                # Skip empty lines
                if not element:
                    continue
                tmp_file.write(element.strip() + '\n')
        chmod(tmp_file_path, 0o640)
    except IOError:
        raise WazuhInternalError(1005)

    # Validate CDB list
    if not validate_cdb_list(tmp_file_path):
        try:
            remove(tmp_file_path)
        except (IOError, OSError):
            pass
        raise WazuhError(1800)

    return tmp_file_path


def delete_list(rel_path):
    """Delete a Wazuh CDB list file.

    Parameters
    ----------
    rel_path : str
        Relative path of the file to delete.
    """
    delete_wazuh_file(join(common.ossec_path, rel_path))

    # Also delete .cdb file (if exists).
    try:
        remove(join(common.ossec_path, rel_path + CDB_EXTENSION))
    except (IOError, OSError):
        pass
