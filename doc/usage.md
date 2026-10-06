# Usage

From your Zephyr workspace root:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project default \
  --variant zephyr_demo \
  --serve
```

If SPDX files already exist and you only want to import them:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --no-generate \
  --project default \
  --variant zephyr_demo \
  --serve
```

Optional wrapper mode (instead of direct container exec):

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project default \
  --variant zephyr_demo \
  --vulnscout-cmd /home/vboudevin/Documents/vs/vulnscout/vulnscout \
  --vulnscout-image sfl:custom \
  --serve --dev
```

The command generates SPDX 3.1 SBOM files with west spdx and then imports all
matching files from the SPDX output directory:

- *.jsonld
- *.spdx.json
- *.spdx
