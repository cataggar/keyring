# keyring

`keyring` is a Zig command-line interface for OS credential storage, intended to be compatible with the Python keyring CLI.

## Status

Phase A skeleton: build, CI, help/version/list-backends wiring, and dependency integration are in place. `set`, `get`, and `del` are not implemented yet; they will be added in a later phase after the required `cataggar/keyring-zig` CLI foundation work lands.

## Usage

```sh
keyring --help
keyring --version
keyring --list-backends
keyring set <service> <user>
keyring get <service> <user>
keyring del <service> <user>
```

## Links

- Plan: https://github.com/cataggar/keyring/issues/1
- Library: https://github.com/cataggar/keyring-zig

## License

MIT; see [LICENSE](LICENSE).
