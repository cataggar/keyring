# Compatibility with Python `keyring`

The CLI follows Python `keyring` command shapes and the native backend
schema/TargetName conventions aligned in
[cataggar/keyring-zig#9](https://github.com/cataggar/keyring-zig/issues/9), so
entries can be shared with Python `keyring` when both commands use the same
backend.

```sh
python3 -m keyring set github me
keyring get github me
```
