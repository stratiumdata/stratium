# stratium-sdk

Python SDK for building a Stratium policy enforcement point (PEP) against the
PDP's gRPC service.

Only runtime dependency: `grpcio`.

## Development

Generated gRPC stubs (`stratium/_pdp/pdp_pb2*.py`) are committed so
installing the package does not require `protoc`. They're regenerated from
`proto/pdp/v1/pdp.proto` and checked for drift from the repo root:

```bash
make proto-python        # regenerate the stubs
make proto-python-check  # fail if the committed stubs are stale
```

Install for local development:

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest tests/ -q
```
