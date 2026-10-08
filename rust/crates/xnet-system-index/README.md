# xnet-system-index

Typed `xnet.system-directory.v1` discovery, query, index-out and advisory route plans. The JSON protocol matches `xnet.system_catalog` in Python. It has no model, command executor, cloud interface, scope grant or lesson promotion API.

`Directory::validate` checks the closed schema, exact digest, bounded fields and source-bound status evidence. `handle_request` supports only `list`, `query`, `select` and `route-plan`. A candidate route still needs the caller's current source check and existing component gate. `verify_source_bytes` verifies already scoped bytes supplied by the caller; it does not read a filesystem or authorize a path.

The binary accepts a bounded stdin JSON envelope containing exactly `directory` and `request`. It writes one discovery response to stdout and returns exit code 2 on invalid input. No argument from the directory becomes a shell command.

The crate is included by the existing `crates/*` workspace glob. This addition does not change other crate sources or their activation. The portable tests include a local copy of the shared Python/Rust protocol fixture. Test results and compilation conditions are recorded separately in the system catalog evidence.
