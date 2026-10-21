# SBOM Generation and Import

## Generate and import an SBOM

Build the application with `CONFIG_BUILD_OUTPUT_META=y` first, then run:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim
```

By default, the command generates SPDX 3.0 SBOMs using `west spdx` and imports
the matching files from `<build-dir>/spdx`:

- `*.jsonld`
- `*.spdx.json`
- `*.spdx`

Importing does not request a full vulnerability scan. See
[Vulnerability Scanning](vulnerability-scanning.md) to run the scanners too.

## Reuse existing SPDX files

Skip generation and import files already present in the SPDX directory:

```sh
west vulnscout -d demo/mbedtls_sbom/build \
  --no-generate --spdx-dir demo/mbedtls_sbom/build/spdx \
  --project zephyr_demo --variant mbedtls_native_sim
```

Use `--spdx-file /path/to/file.jsonld` to select an explicit file. Repeat the
option for companion documents; when explicit files are supplied, directory
discovery is skipped. Import all West companion documents together to retain
their cross-document relationships.

## SPDX generation options

| Option | Purpose |
| --- | --- |
| `--spdx-dir PATH` | Change the generation/import directory. |
| `--spdx-version {3.0,3.1}` | Select the SPDX version; the default is 3.0. |
| `--namespace-prefix PREFIX` | Pass a namespace prefix to `west spdx`. |
| `--include-sdk` | Include the SDK in SPDX generation. |
| `--analyze-includes` | Analyze included header files during generation. |

SPDX 3.1 requires `spdx-python-model` bindings for `v3_1`. If generation fails
with 3.1 selected, the extension warns and retries with SPDX 3.0.
