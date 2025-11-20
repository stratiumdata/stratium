/**
 * @fileoverview Constants for the Stratium SDK
 * @module utils/constants
 */

// API Paths
export const OIDC_TOKEN_PATH = '/protocol/openid-connect/token';

// OAuth Grant Types
export const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';
export const GRANT_TYPE_REFRESH_TOKEN = 'refresh_token';

// HTTP Headers
export const CONTENT_TYPE_JSON = 'application/json';
export const CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded';
export const AUTH_HEADER_PREFIX = 'Bearer ';

// Default Values
export const DEFAULT_TIMEOUT = 30000; // 30 seconds
export const DEFAULT_RETRY_ATTEMPTS = 3;
export const DEFAULT_CLIENT_ID = 'stratium-client';
export const DEFAULT_OIDC_SCOPES = ['openid', 'profile', 'email'];

// Subject Attributes
export const SUBJECT_ATTR_SUB = 'sub';
export const SUBJECT_ATTR_USER_ID = 'user_id';
export const SUBJECT_ATTR_ID = 'id';

// Error Messages
export const ERR_MSG_CLIENT_ID_REQUIRED = 'client_id is required';
export const ERR_MSG_RESOURCE_ATTRIBUTES_REQUIRED = 'resource_attributes is required';
export const ERR_MSG_ACTION_REQUIRED = 'action is required';
export const ERR_MSG_SUBJECT_ATTRIBUTES_REQUIRED = 'subject_attributes is required';
export const ERR_MSG_REQUEST_NIL = 'request cannot be null or undefined';
export const ERR_MSG_FAILED_TO_GET_AUTH_TOKEN = 'failed to get authentication token';
export const ERR_MSG_SUBJECT_IDENTIFIER_REQUIRED = "subject_attributes must contain 'sub', 'user_id', or 'id'";

// ZTDF Constants
export const MANIFEST_FILE_NAME = 'manifest.json';
export const PAYLOAD_FILE_NAME = '0.payload';
export const DEFAULT_FILE_MODE = 0o644;
export const DEFAULT_KEY_ACCESS_URL = 'localhost:50053';
export const DEFAULT_RESOURCE_NAME = 'ztdf-resource';

// Cryptographic Constants
export const AES_KEY_SIZE = 32; // 256 bits
export const AES_IV_SIZE = 12; // 96 bits for GCM
export const AES_TAG_SIZE = 16; // 128 bits

// ZTDF Algorithms
export const ALGORITHM_AES_256_GCM = 'AES-256-GCM';
export const ALGORITHM_HS256 = 'HS256';
export const ALGORITHM_GMAC = 'GMAC';
export const ALGORITHM_JWS = 'jws';

// ZTDF Manifest
export const TDF_SPEC_VERSION = '4.0.0';
export const PROTOCOL_KAS = 'kas';
export const PROTOCOL_ZIP = 'zip';
export const TYPE_REFERENCE = 'reference';
export const TYPE_WRAPPED = 'wrapped';
export const MIME_TYPE_OCTET_STREAM = 'application/octet-stream';
export const PLACEHOLDER_SIGNATURE = 'placeholder-signature';

// Policy URIs
export const CLASSIFICATION_URI_TEMPLATE = 'http://example.com/attr/classification/value/%s';
export const ATTRIBUTE_URI_TEMPLATE = 'http://example.com/attr/%s/value/%s';

// Decision Types
export const DECISION_DENY = 0;
export const DECISION_ALLOW = 1;
export const DECISION_CONDITIONAL = 2;