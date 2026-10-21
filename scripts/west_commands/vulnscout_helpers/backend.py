# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
import json
import pathlib

from .process import VulnScoutError


INTERFACE_LABEL = 'io.vulnscout.interface'
CACHE_DIR = '/cache/vulnscout'


@dataclass(frozen=True)
class BackendInterface:
    entrypoint: tuple[str, ...]
    cli: tuple[str, ...]
    python: tuple[str, ...]
    workdir: str


def parse_interface(payload: str) -> BackendInterface:
    message = (
        f'Incompatible VulnScout image: expected {INTERFACE_LABEL} interface version 1 '
        'with isolated-inputs and python-fcntl. Rebuild or upgrade the image and '
        'recreate the container with the same cache.'
    )
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise VulnScoutError(message) from error
    if not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] != 1:
        raise VulnScoutError(message)
    features = value.get('features')
    if not isinstance(features, list) or any(not isinstance(item, str) for item in features):
        raise VulnScoutError(message)
    if not {'isolated-inputs', 'python-fcntl'}.issubset(features):
        raise VulnScoutError(message)
    commands = []
    for key in ('entrypoint', 'cli', 'python'):
        command = value.get(key)
        if not isinstance(command, list) or not command or any(
            not isinstance(part, str) or not part.strip() or '\0' in part for part in command
        ):
            raise VulnScoutError(f'{message} Invalid {key} command vector.')
        commands.append(tuple(command))
    workdir = value.get('workdir')
    if (
        not isinstance(workdir, str) or '\0' in workdir
        or not pathlib.PurePosixPath(workdir).is_absolute()
        or '..' in pathlib.PurePosixPath(workdir).parts
    ):
        raise VulnScoutError(f'{message} Invalid working directory.')
    return BackendInterface(
        entrypoint=commands[0], cli=commands[1], python=commands[2], workdir=workdir,
    )
