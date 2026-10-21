# Getting Started

## Add to your West workspace

Add this repository as a project in your West manifest and register
west-commands.yml:

```yaml
manifest:
  projects:
    - name: zephyr-west-vulnscout
      url: https://github.com/ValentinBoudevinSFL/zephyr-west-vulnscout
      revision: main
      path: zephyr-west-vulnscout
      west-commands: west-commands.yml
```

Then update and verify command availability:

```sh
west update zephyr-west-vulnscout
west help vulnscout
```

## Projects, variants, and cache

Run the feature guide examples from your Zephyr workspace root. Always pass
the same `--project` and `--variant` when continuing a workflow. Omitting them
selects `default/default`; the command does not infer them from the build
directory. The guides use project `zephyr_demo` and variant `mbedtls_native_sim`.

The build directory also selects the default persistent cache. When reusing
an existing container, check its cache location as described in
[Container Lifecycle and Configuration](usage/container-configuration.md).
