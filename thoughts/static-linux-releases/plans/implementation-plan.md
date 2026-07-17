# Fully Static Linux Releases Implementation Plan

## Overview

Replace the dynamically linked GNU/Linux release artifacts with fully static
musl artifacts for x86_64 and aarch64. Keep normal developer builds unchanged,
make static linkage a release invariant, and preserve automatic installation
through `ghr`.

## Current State Analysis

- The release matrix builds `x86_64-linux-gnu` and `aarch64-linux-gnu`
  artifacts (`.github/workflows/release.yml:24-29`).
- The release workflow installs `libsecret-1-dev` and `libglib2.0-dev` even
  though the current Linux backend does not link either library
  (`.github/workflows/release.yml:57-61`).
- `build.zig` passes the selected target to the executable and the
  `keyring_zig` dependency without imposing a Linux linkage mode
  (`build.zig:13-28`).
- The pinned `keyring_zig` Linux backend links libc only for environment access
  and talks directly to Secret Service over Unix D-Bus. It does not link
  libsecret or GLib.
- Local Zig 0.16.0 builds for `x86_64-linux-musl` and
  `aarch64-linux-musl` have been proven to produce ELF files reported as
  `statically linked`, with no program interpreter and no `DT_NEEDED`
  entries.
- `ghr` recognizes both `linux-musl` and `unknown-linux-musl` asset naming.
- The obsolete dynamic-linking paragraph has already been removed from the
  release-note template (`.github/workflows/release.yml:133-138`).

## Desired End State

Each release publishes:

- `keyring-<tag>-x86_64-linux-musl`
- `keyring-<tag>-aarch64-linux-musl`

Both files must:

1. Build with Zig 0.16.0 without a host libc sysroot or third-party development
   libraries.
2. Contain no ELF `PT_INTERP` program header.
3. Contain no dynamic `DT_NEEDED` dependencies.
4. Run `keyring version` on their native architectures.
5. Be selected correctly by `ghr install cataggar/keyring@<tag>`.
6. Continue to communicate with a Secret Service daemon over D-Bus when the
   `secret_service` backend is used.

The absence of runtime libc dependencies does not remove the behavioral
requirement for a running Secret Service daemon.

## Key Discoveries

- Linux release target selection is isolated to the release matrix and build
  command (`.github/workflows/release.yml:20-70`).
- Artifact names are generated directly from the matrix `target` value
  (`.github/workflows/release.yml:73-79`), so changing the matrix to musl also
  gives `ghr` the correct platform discriminator.
- The existing integration workflow already provides a real GNOME Secret
  Service session and Python interoperability coverage
  (`.github/workflows/integration.yml:27-64`).
- The Linux integration packages remain test-environment dependencies; they
  are separate from release binary link dependencies.

## What We're NOT Doing

- Building or distributing a statically linked glibc executable.
- Depending on `cataggar/glib` for release builds.
- Republishing or renaming assets attached to existing releases.
- Changing macOS or Windows artifacts.
- Removing GNOME, D-Bus, Python, or `secret-tool` packages required by Linux
  integration tests.
- Bundling or replacing the Secret Service daemon.
- Changing the default native `zig build` target for developers.

## Implementation Approach

Use Zig's bundled musl toolchain by changing only the Linux release targets to
`*-linux-musl`. Do not force all Linux builds to be static in `build.zig`;
native GNU/Linux development and test builds should retain their current
behavior.

Enforce the release guarantee with an ELF verifier shared by release and CI
workflows. The verifier, rather than assumptions about Zig defaults or `file`
output wording, will reject binaries containing either an interpreter or
dynamic library dependencies.

## Phase 1: Produce musl Release Artifacts

### Overview

Switch both Linux release jobs from GNU libc to musl and remove packages that
are not needed to build the release binary.

### Changes Required

#### 1. Linux release matrix

**File**: `.github/workflows/release.yml`

Change the Linux rows while retaining the existing native runners:

```yaml
- os: ubuntu-latest
  target: x86_64-linux-musl
  zig_target: x86_64-linux-musl
  binary: keyring
- os: ubuntu-24.04-arm
  target: aarch64-linux-musl
  zig_target: aarch64-linux-musl
  binary: keyring
```

This intentionally changes the published asset suffix from `linux-gnu` to
`linux-musl`; `ghr` already recognizes that suffix.

#### 2. Release-only Linux dependencies

**File**: `.github/workflows/release.yml`

Delete the `Install Linux dependencies` step. Zig provides the musl libc used
by both targets, and the release build does not link libsecret or GLib.

Do not remove the similarly named integration-test step: it installs the
daemon and tools used by the tests rather than release link dependencies.

### Success Criteria

- Both Linux matrix jobs complete without apt-installed development packages.
- The uploaded artifacts use the `x86_64-linux-musl` and
  `aarch64-linux-musl` suffixes.
- macOS and Windows artifact names and build commands are unchanged.

**Implementation Note**: Pause after this phase only if either musl target
requires an unexpected source or dependency change.

---

## Phase 2: Enforce Static ELF Linkage

### Overview

Add a reusable verifier and run it before Linux artifacts can be packaged.

### Changes Required

#### 1. Static ELF verification script

**File**: `tests/verify_static_elf.sh`

Add a script accepting one binary path:

```bash
#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: verify_static_elf.sh <binary>}"
readelf -hW "$binary" >/dev/null

if readelf -lW "$binary" | grep -q 'INTERP'; then
  echo "$binary contains a dynamic program interpreter" >&2
  exit 1
fi

if readelf -dW "$binary" 2>/dev/null | grep -q '(NEEDED)'; then
  echo "$binary contains dynamic library dependencies" >&2
  exit 1
fi
```

Keep the checks architecture-independent so the same host tools can inspect
both x86_64 and aarch64 ELF files.

#### 2. Release linkage gate

**File**: `.github/workflows/release.yml`

After `Build` and before `Package binary`, add:

```yaml
- name: Verify static Linux binary
  if: runner.os == 'Linux'
  shell: bash
  run: bash tests/verify_static_elf.sh "zig-out/bin/${{ matrix.binary }}"
```

Packaging and publishing must remain downstream of this gate, ensuring a
future Zig, dependency, or target change cannot silently restore dynamic
linkage.

### Success Criteria

- The verifier accepts both musl release binaries.
- A GNU/Linux release build fails the verifier because it contains an
  interpreter and `DT_NEEDED` entries.
- No Linux artifact is uploaded when verification fails.

**Implementation Note**: Confirm the failure case once by running the verifier
against an `x86_64-linux-gnu` build before proceeding.

---

## Phase 3: Add Continuous and End-to-End Coverage

### Overview

Exercise the static targets before tags are created, verify real Secret Service
behavior with a musl binary, and document the distribution guarantee.

### Changes Required

#### 1. Static release-target CI job

**File**: `.github/workflows/ci.yml`

Add a matrix job with:

```yaml
include:
  - os: ubuntu-latest
    target: x86_64-linux-musl
  - os: ubuntu-24.04-arm
    target: aarch64-linux-musl
```

For each target:

1. Build with `zig build -Doptimize=ReleaseSafe -Dtarget=<target>`.
2. Run `bash tests/verify_static_elf.sh zig-out/bin/keyring`.
3. Run `./zig-out/bin/keyring version` on the native runner.

This catches target and linkage regressions on pull requests rather than on the
next release tag.

#### 2. Exercise the musl binary in Linux integration tests

**File**: `.github/workflows/integration.yml`

Change only the Linux build command to:

```bash
zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-musl
```

Keep macOS and Windows builds native. The existing Linux test commands then
exercise the actual static binary against GNOME Keyring, D-Bus, `secret-tool`,
and Python `keyring`.

#### 3. Document Linux distribution behavior

**File**: `README.md`

Add a short installation section containing the existing `ghr install`
command and state that Linux release assets are fully static musl binaries.
Clarify that the `secret_service` backend still requires access to a Secret
Service daemon.

Do not restore the removed dependency paragraph in the generated release
notes.

#### 4. Validate installer selection on a prerelease

After publishing the first prerelease with musl assets:

1. Run `ghr install cataggar/keyring@<tag>` on x86_64 GNU/Linux.
2. Run it on x86_64 Alpine Linux.
3. Run it on aarch64 Linux.
4. Confirm the selected asset contains `linux-musl`.
5. Run `keyring version` in each environment.

### Success Criteria

- Pull requests build, inspect, and execute both static Linux architectures.
- The x86_64 musl binary passes existing Secret Service and Python
  interoperability tests.
- `ghr` selects the correct musl asset on glibc and musl hosts.
- README wording distinguishes static binary dependencies from the separate
  Secret Service daemon requirement.

**Implementation Note**: Treat the first musl prerelease as the compatibility
checkpoint before publishing a stable release.

---

## Testing Strategy

### Unit Tests

- Run the existing `zig build test`.
- No application unit-test changes are expected because the runtime behavior
  and backend implementation are unchanged.

### Workflow and Integration Tests

- Build and verify `x86_64-linux-musl`.
- Build and verify `aarch64-linux-musl`.
- Prove the verifier rejects an `x86_64-linux-gnu` binary.
- Run `keyring version` natively on both Linux architectures.
- Run the existing Linux integration and Python interoperability suites using
  the x86_64 musl binary.
- Confirm release checksum generation includes the renamed musl assets.

### Manual Testing Steps

1. Create a prerelease tag and wait for all six platform artifacts.
2. Inspect both Linux assets with `readelf -lW` and `readelf -dW`.
3. Install through `ghr` on GNU/Linux, Alpine Linux, and aarch64 Linux.
4. Run `keyring version`.
5. On a host with a Secret Service daemon, run a set/get/delete round trip.
6. Confirm no existing `linux-gnu` asset is selected for the new tag.

## Performance Considerations

Static musl binaries may differ in size from the current GNU/Linux binaries,
but startup and keyring operation performance should remain functionally
equivalent. Record artifact sizes during the first prerelease and investigate
only if the increase is material.

## Migration Notes

- Existing release assets remain unchanged.
- New releases replace the `linux-gnu` suffix with `linux-musl`; consumers that
  hard-code asset filenames must update.
- `ghr` users require no command change because the installer recognizes musl
  asset names.
- No credential, cache, configuration, or backend migration is required.

## References

- Release workflow: `.github/workflows/release.yml`
- Build configuration: `build.zig`
- Integration workflow: `.github/workflows/integration.yml`
- Pinned Linux backend:
  <https://github.com/cataggar/keyring-zig/blob/d1b4320/src/keyring-linux.zig>
- Pinned dependency build:
  <https://github.com/cataggar/keyring-zig/blob/d1b4320/build.zig>
- `ghr` platform matching:
  <https://github.com/cataggar/ghr/blob/main/src/release.zig>
