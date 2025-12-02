package com.stratium.sdk.client;

import java.util.Collections;
import java.util.Map;

public final class WrapOptions {
    private final String resource;
    private final Map<String, String> resourceAttributes;
    private final String filename;
    private final String contentType;
    private final boolean integrityCheck;
    private final String action;
    private final Map<String, String> context;
    private final String policyBase64;

    private WrapOptions(Builder builder) {
        this.resource = builder.resource;
        this.resourceAttributes = builder.resourceAttributes;
        this.filename = builder.filename;
        this.contentType = builder.contentType;
        this.integrityCheck = builder.integrityCheck;
        this.action = builder.action;
        this.context = builder.context;
        this.policyBase64 = builder.policyBase64;
    }

    public String getResource() {
        return resource;
    }

    public Map<String, String> getResourceAttributes() {
        return resourceAttributes;
    }

    public String getFilename() {
        return filename;
    }

    public String getContentType() {
        return contentType;
    }

    public boolean isIntegrityCheck() {
        return integrityCheck;
    }

    public String getAction() {
        return action;
    }

    public Map<String, String> getContext() {
        return context;
    }

    public String getPolicyBase64() {
        return policyBase64;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String resource = "encrypted-file";
        private Map<String, String> resourceAttributes = Collections.emptyMap();
        private String filename = "file";
        private String contentType = "application/octet-stream";
        private boolean integrityCheck = true;
        private String action = "decrypt";
        private Map<String, String> context = Collections.emptyMap();
        private String policyBase64 = "";

        public Builder resource(String resource) {
            this.resource = resource;
            return this;
        }

        public Builder resourceAttributes(Map<String, String> resourceAttributes) {
            this.resourceAttributes = resourceAttributes;
            return this;
        }

        public Builder filename(String filename) {
            this.filename = filename;
            return this;
        }

        public Builder contentType(String contentType) {
            this.contentType = contentType;
            return this;
        }

        public Builder integrityCheck(boolean integrityCheck) {
            this.integrityCheck = integrityCheck;
            return this;
        }

        public Builder action(String action) {
            this.action = action;
            return this;
        }

        public Builder context(Map<String, String> context) {
            this.context = context;
            return this;
        }

        public Builder policyBase64(String policyBase64) {
            this.policyBase64 = policyBase64;
            return this;
        }

        public WrapOptions build() {
            return new WrapOptions(this);
        }
    }
}
