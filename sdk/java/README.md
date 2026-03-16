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

## Configuration

```java
StratiumClientConfig config = StratiumClientConfig.builder()
    .keyAccessUri(URI.create("http://localhost:8081"))
    .keyManagerUri(URI.create("http://localhost:8082"))
    .clientId("my-app")
    .fipsEnabled(true)
    .build();
```

When `fipsEnabled` is true, the client sends the DEK in plaintext over TLS to the Key Access service.
The SDK also verifies that the default JCE provider for AES/GCM is FIPS-capable and fails fast if not.
If the BCFIPS provider is on the classpath, FIPS mode attempts to register it at highest priority and
sets `org.bouncycastle.fips.approved_only=true` unless already configured.

To include the BCFIPS provider jars at build time, run:

```
./gradlew build -Pfips=true
```

Override defaults with:

- `-PbcFipsVersion=2.1.2`
- `-PbcpkixFipsVersion=2.1.10`
- `-PbctlsFipsVersion=2.1.22`

To ensure the JVM prioritizes BCFIPS, you can point Java at the provided security override:

```
JAVA_TOOL_OPTIONS="-Djava.security.properties=./config/java.security.fips"
```

## TODO

- [ ] Implement persistent key storage analogous to IndexedDB/local filesystem.
- [ ] Mirror `wrap` / `unwrap` APIs from JS/Go clients.
- [ ] Add CLI helpers similar to `ztdf-client` for desktop automation.
- [ ] Flesh out integration tests against mock Key Access / Key Manager services.
