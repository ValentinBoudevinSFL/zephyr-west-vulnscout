# zephyr-west-vulnscout

West extension command for Zephyr that generates SPDX 3 SBOMs and imports them
into VulnScout for vulnerability analysis.

## What it provides

- `west vulnscout`
  - Generates SPDX 3.1 SBOM files via `west spdx`
  - Imports SBOM files into VulnScout using `--add-spdx`
  - Supports optional VulnScout flags like `--serve` and `--dev`
  - Supports custom VulnScout image via `--vulnscout-image`

## Repository layout

- `west-commands.yml`: command registration for West
- `scripts/west_commands/vulnscout.py`: command implementation

## Add to your West workspace

Add this repository as a project in your West manifest and register
`west-commands.yml`:

```yaml
manifest:
  projects:
    - name: zephyr-west-vulnscout
      url: https://github.com/ValentinBoudevinSFL/zephyr-west-vulnscout
      revision: main
      path: zephyr-west-vulnscout
      west-commands: west-commands.yml
```

Then update and check command availability:

```sh
west update zephyr-west-vulnscout
west help vulnscout
```

## Example usage

From your Zephyr workspace root:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project default \
  --variant zephyr_demo \
  --vulnscout-cmd /home/vboudevin/Documents/vs/vulnscout/vulnscout \
  --vulnscout-image sfl:custom \
  --serve --dev
```

If SPDX files already exist and you only want to import them:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --no-generate \
  --project default \
  --variant zephyr_demo \
  --vulnscout-cmd /home/vboudevin/Documents/vs/vulnscout/vulnscout \
  --vulnscout-image sfl:custom \
  --serve --dev
```

## License

Copyright (C) 2025-2026 Savoir-faire Linux, Inc.

This repository is licensed under Apache-2.0. See LICENSE.

## Maintainer and Patches

Maintainer: Valentin Boudevin valentin.boudevin@savoirfairelinux.com

Submit patches and bug reports through the meta-vulnscout GitHub repository.
Each patch should include a clear commit message and a Signed-off-by line.

## Documentation

This repository includes Read the Docs configuration and Sphinx sources in the
same style as VulnScout and meta-vulnscout.

- Read the Docs config: .readthedocs.yaml
- Sphinx configuration: doc/conf.py
- Sphinx entry page: doc/index.rst
