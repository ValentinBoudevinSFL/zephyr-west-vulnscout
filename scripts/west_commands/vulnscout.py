# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import glob
import os
import pathlib
import subprocess
import textwrap

from west.commands import WestCommand
from west.util import quote_sh_list


VULNSCOUT_DESCRIPTION = """\
Generate SPDX 3.1 SBOM files using west spdx, then import them into VulnScout.

By default this command runs `west spdx --spdx-version 3.1`, then imports all
`*.jsonld` files from the SPDX output directory into VulnScout using
`--add-spdx`."""


class ZephyrVulnScout(WestCommand):
    def __init__(self):
        super().__init__('vulnscout', '', description=VULNSCOUT_DESCRIPTION)

    def do_add_parser(self, parser_adder):
        parser = parser_adder.add_parser(
            self.name,
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent(
                """\
            Examples:

                # Build first (with CONFIG_BUILD_OUTPUT_META=y), then:
                west vulnscout -d build

                # Use a custom VulnScout image and launch web UI in dev mode:
                west vulnscout -d build --vulnscout-image sfl:custom --serve --dev

                # Skip SPDX generation and import an existing SPDX output directory:
                west vulnscout -d build --no-generate --spdx-dir build/spdx
            """
            ),
        )

        parser.add_argument('-d', '--build-dir', required=True, help='Zephyr build directory')
        parser.add_argument(
            '--spdx-dir',
            help='SPDX output directory (default: <build-dir>/spdx)',
        )
        parser.add_argument(
            '--namespace-prefix',
            help='namespace prefix passed to west spdx',
        )
        parser.add_argument(
            '--include-sdk',
            action='store_true',
            help='also generate SPDX document for SDK',
        )
        parser.add_argument(
            '--analyze-includes',
            action='store_true',
            help='also analyze included header files',
        )
        parser.add_argument(
            '--no-generate',
            action='store_true',
            help='skip west spdx generation and reuse files from --spdx-dir',
        )
        parser.add_argument(
            '--spdx-file',
            action='append',
            default=[],
            help='specific SPDX file to import (can be used multiple times)',
        )
        parser.add_argument(
            '--project',
            default='default',
            help='VulnScout project name (default: default)',
        )
        parser.add_argument(
            '--variant',
            default='default',
            help='VulnScout variant name (default: default)',
        )
        parser.add_argument(
            '--vulnscout-cmd',
            default='vulnscout',
            help='VulnScout wrapper command or absolute path (default: vulnscout)',
        )
        parser.add_argument(
            '--vulnscout-image',
            help='value exported as VULNSCOUT_IMAGE for the VulnScout command',
        )
        parser.add_argument(
            '--serve',
            action='store_true',
            help='pass --serve to VulnScout',
        )
        parser.add_argument(
            '--dev',
            action='store_true',
            help='pass --dev to VulnScout',
        )
        parser.add_argument(
            '--refresh-vulnerability-data',
            action='store_true',
            help='pass --refresh-vulnerability-data to VulnScout',
        )
        parser.add_argument(
            '--match-condition',
            help='pass --match-condition to VulnScout',
        )

        return parser

    def do_run(self, args, unknown_args):
        if unknown_args:
            self.die(f'Unexpected arguments: {unknown_args}')

        build_dir = os.path.abspath(args.build_dir)
        spdx_dir = os.path.abspath(args.spdx_dir or os.path.join(build_dir, 'spdx'))

        if not os.path.isdir(build_dir):
            self.die(f'Build directory does not exist: {build_dir}')

        if not args.no_generate:
            self._run_west_spdx(args, build_dir, spdx_dir)

        spdx_files = self._resolve_spdx_files(args.spdx_file, spdx_dir)
        if not spdx_files:
            self.die(
                f'No SPDX files found to import in {spdx_dir}. '
                f'Expected *.jsonld, *.spdx.json, or *.spdx files.'
            )

        self._run_vulnscout(args, spdx_files)

    def _run_west_spdx(self, args, build_dir, spdx_dir):
        cmd = [
            'west',
            'spdx',
            '--build-dir',
            build_dir,
            '--spdx-dir',
            spdx_dir,
            '--spdx-version',
            '3.1',
        ]
        if args.namespace_prefix:
            cmd.extend(['--namespace-prefix', args.namespace_prefix])
        if args.include_sdk:
            cmd.append('--include-sdk')
        if args.analyze_includes:
            cmd.append('--analyze-includes')

        self.inf(f'Generating SPDX 3.1 SBOM with: {quote_sh_list(cmd)}')
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            self.die(f'west spdx failed with exit code {e.returncode}')

    def _resolve_spdx_files(self, explicit_files, spdx_dir):
        resolved = []

        for raw_path in explicit_files:
            file_path = os.path.abspath(raw_path)
            if not os.path.isfile(file_path):
                self.die(f'SPDX file does not exist: {file_path}')
            resolved.append(file_path)

        if resolved:
            return sorted(set(resolved))

        patterns = [
            os.path.join(spdx_dir, '*.jsonld'),
            os.path.join(spdx_dir, '*.spdx.json'),
            os.path.join(spdx_dir, '*.spdx'),
        ]

        for pattern in patterns:
            resolved.extend(glob.glob(pattern))

        resolved = sorted(set(os.path.abspath(p) for p in resolved if os.path.isfile(p)))
        return resolved

    def _run_vulnscout(self, args, spdx_files):
        vulnscout_cmd = [
            args.vulnscout_cmd,
            '--project',
            args.project,
            '--variant',
            args.variant,
        ]

        for spdx_file in spdx_files:
            vulnscout_cmd.extend(['--add-spdx', spdx_file])

        if args.refresh_vulnerability_data:
            vulnscout_cmd.append('--refresh-vulnerability-data')
        if args.match_condition:
            vulnscout_cmd.extend(['--match-condition', args.match_condition])
        if args.serve:
            vulnscout_cmd.append('--serve')
        if args.dev:
            vulnscout_cmd.append('--dev')

        env = os.environ.copy()
        if args.vulnscout_image:
            env['VULNSCOUT_IMAGE'] = args.vulnscout_image

        pretty_files = ', '.join(pathlib.Path(f).name for f in spdx_files)
        self.inf(f'Importing SPDX files into VulnScout: {pretty_files}')
        self.inf(f'Running VulnScout command: {quote_sh_list(vulnscout_cmd)}')
        try:
            subprocess.run(vulnscout_cmd, env=env, check=True)
        except FileNotFoundError:
            self.die(
                f'Could not find VulnScout command: {args.vulnscout_cmd}. '
                f'Use --vulnscout-cmd with an absolute path, e.g. '
                f'/home/vboudevin/Documents/vs/vulnscout/vulnscout'
            )
        except subprocess.CalledProcessError as e:
            self.die(f'VulnScout failed with exit code {e.returncode}')
