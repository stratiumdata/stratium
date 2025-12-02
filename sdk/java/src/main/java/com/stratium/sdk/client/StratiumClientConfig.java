package com.stratium.sdk.client;

import java.net.URI;
import java.util.Objects;

public final class StratiumClientConfig {
    private final URI keyAccessUri;
    private final URI keyManagerUri;
    private final String clientId;
    private final String subjectId;
    private final String realm;

    private StratiumClientConfig(Builder builder) {
        this.keyAccessUri = builder.keyAccessUri;
        this.keyManagerUri = builder.keyManagerUri;
        this.clientId = builder.clientId;
        this.subjectId = builder.subjectId;
        this.realm = builder.realm;
    }

    public URI getKeyAccessUri() {
        return keyAccessUri;
    }

    public URI getKeyManagerUri() {
        return keyManagerUri;
    }

    public String getClientId() {
        return clientId;
    }

    public String getSubjectId() {
        return subjectId;
    }

    public String getRealm() {
        return realm;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private URI keyAccessUri;
        private URI keyManagerUri;
        private String clientId;
        private String subjectId;
        private String realm;

        public Builder keyAccessUri(URI uri) {
            this.keyAccessUri = uri;
            return this;
        }

        public Builder keyManagerUri(URI uri) {
            this.keyManagerUri = uri;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder subjectId(String subjectId) {
            this.subjectId = subjectId;
            return this;
        }

        public Builder realm(String realm) {
            this.realm = realm;
            return this;
        }

        public StratiumClientConfig build() {
            Objects.requireNonNull(keyAccessUri, "keyAccessUri");
            Objects.requireNonNull(keyManagerUri, "keyManagerUri");
            Objects.requireNonNull(clientId, "clientId");
            return new StratiumClientConfig(this);
        }
    }
}
