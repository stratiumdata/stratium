# Stratium Java SDK

A Java implementation of the Stratium SDK providing feature parity with the existing Go and JavaScript SDKs. The library exposes APIs for registering client keys, wrapping/unwrapping Zero Trust Data Format (ZTDF) files, streaming large payloads, and verifying policy & integrity constraints.

## Project layout

```
java/
├── build.gradle.kts
├── settings.gradle.kts
├── src
│   ├── main
│   │   ├── java/com/stratium/sdk
│   │   │   ├── client/…
│   │   │   ├── crypto/…
│   │   │   ├── key/…
│   │   │   └── ztdf/…
│   │   └── resources
│   └── test/java
└── README.md
```

The module uses Gradle with the protobuf plugin to generate gRPC clients directly from the shared `proto/` definitions that back the Go and JavaScript SDKs.

## Build

```
./gradlew build
```

## TODO

- [ ] Implement persistent key storage analogous to IndexedDB/local filesystem.
- [ ] Mirror `wrap` / `unwrap` APIs from JS/Go clients.
- [ ] Add CLI helpers similar to `ztdf-client` for desktop automation.
- [ ] Flesh out integration tests against mock Key Access / Key Manager services.
