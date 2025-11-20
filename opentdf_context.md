# Access Control | OpenTDF
OpenTDF Access Control Concepts (ABAC)
--------------------------------------

OpenTDF implements a sophisticated access control model known as **Attribute-Based Access Control (ABAC)**. This approach provides fine-grained, flexible, and scalable authorization for data protection.

Attribute-Based Access Control is a security paradigm where access rights are granted based on the evaluated **attributes** of entities involved in an access request, rather than solely on roles or explicit permissions lists. Key components include:

*   **Subject Attributes:** Characteristics of the entity requesting access (e.g., user's clearance, department, nationality, group memberships).
*   **Resource Attributes:** Characteristics of the data or resource being accessed (e.g., data classification, sensitivity level, project code).
*   **Policies:** Rules that define allowable actions by comparing subject, resource, and potentially environment attributes (e.g., "Allow access if subject's clearance >= resource's classification AND subject is in department 'X'").
*   **Policy Enforcement Point (PEP):** The logical component that evaluates the policies against the attributes and makes the final access decision (grant or deny).

ABAC offers significant advantages over traditional models, enabling dynamic access decisions that adapt to changing conditions without needing constant updates to user roles or access control lists (ACLs).

OpenTDF embeds ABAC directly into the data's protection layer. Here's how its components map to ABAC concepts:

*   **Subject Attributes:** Represented by **Entity Entitlements**. These are the attribute instances asserted by the identity system or client about the user/entity requesting access. They are provided _to_ the PEP during an access request.
*   **Resource Attributes:** Defined within the TDF's [Policy Object](https://opentdf.io/spec/schema/opentdf/policy) in the `dataAttributes` array. These specify the attribute instances _required_ to access this specific piece of data.
*   **Policies:** Defined by the combination of:
    *   The `dataAttributes` required by the specific TDF.
    *   The optional `dissem` list in the TDF's [Policy Object](https://opentdf.io/spec/schema/opentdf/policy) acting as an initial filter.
    *   **Attribute Definitions** managed externally by Attribute Authorities, which specify the _rules_ (e.g., AllOf, AnyOf, Hierarchy) for comparing subject and resource attributes.
*   **Policy Enforcement Point (PEP):** Typically resides within the Key Access Server (KAS) or associated logic. It receives the TDF's policy requirements, the subject's entitlements, retrieves the relevant Attribute Definitions, and makes the authorization decision before releasing a key.

To ensure interoperability and clarity, OpenTDF represents attributes as **URIs (Uniform Resource Identifiers)**.

The standard structure is: `{Attribute Namespace}/attr/{Attribute Name}/value/{Attribute Value}`

**Components:**



* Component: Attribute Namespace
  * Example Value: https://example.com
  * Description: Typically a domain controlled by the authoritative source of the attribute definition. Recommended to use a stable, controlled namespace.
  * Globally Unique?: No (by itself)
* Component: Attribute Canonical Name
  * Example Value: https://example.com/attr/classification
  * Description: Combination of Namespace and Name ({Namespace}/attr/{Name}). This MUST be globally unique and identifies the specific attribute type.
  * Globally Unique?: Yes
* Component: Attribute Instance
  * Example Value: https://example.com/attr/classification/value/secret
  * Description: The full URI ({Canonical Name}/value/{Value}). This represents a specific, actionable attribute assertion used in policies or entitlements.
  * Globally Unique?: Yes


Crucially, the _rules_ governing how attributes are compared are defined in **Attribute Definitions**, which are associated with the globally unique **Attribute Canonical Name**. These definitions are managed by the attribute authority and are stored **outside** the TDF manifest itself.

An Attribute Definition typically includes:

*   **Rule Type:** How multiple values or comparisons should be handled (e.g., `AllOf` - entity must have all specified values, `AnyOf` - entity must have at least one, `Hierarchy` - values have an order).
*   **Allowed Values:** An optional enumeration or pattern restricting valid attribute values.
*   **Order/Rank (for Hierarchy):** Defines the relationship between values in a hierarchical attribute (e.g., Confidential < Secret < TopSecret).

The PEP retrieves these definitions at access decision time based on the Canonical Names found in the TDF's `dataAttributes` and the entity's entitlements.

When an entity requests access to an OpenTDF object:

1.  **Request Initiation:** The client presents the relevant [Key Access Object(s)](https://opentdf.io/spec/schema/opentdf/key_access_object) from the TDF manifest to the appropriate KAS, along with the client's credentials and asserted **Entity Entitlements** (Subject Attributes).
2.  **PEP Evaluation:** The KAS performs the following checks based on the TDF's embedded [Policy Object](https://opentdf.io/spec/schema/opentdf/policy) (extracted from the `policy` field):
    *   **Dissemination Check (if applicable):** If the policy's `dissem` list is present and non-empty, the PEP verifies if the requesting entity's identifier is in the list. If not, access is **denied**.
    *   **Attribute Check:**
        *   The PEP examines the required `dataAttributes` (Resource Attributes) listed in the policy.
        *   For each required attribute, it retrieves the corresponding external **Attribute Definition** based on the attribute's Canonical Name.
        *   It compares the required `dataAttributes` against the provided **Entity Entitlements** using the comparison logic (AllOf, AnyOf, Hierarchy) specified in the retrieved Attribute Definitions.
        *   If the entity's entitlements **do not satisfy** the requirements of _all_ `dataAttributes` according to their rules, access is **denied**.
3.  **Key Release (if authorized):** If _both_ the Dissemination Check (if applicable) and the Attribute Check pass, the PEP considers the entity authorized. It then proceeds with verifying the [Policy Binding](about:/spec/concepts/security#3-policy-binding) and, if valid, unwraps and provides the requested key share(s) to the client.

> **Policy Logic Clarification:** The relationship between the `dissem` list and the `dataAttributes` is effectively an **AND**. An entity MUST be on the `dissem` list (if it's used) **AND** MUST satisfy the `dataAttributes` requirements. If the `dissem` list is empty or omitted, then _only_ the `dataAttributes` requirements need to be met. The `dissem` list acts as an additional filter to narrow the audience beyond what the attributes alone define.

By combining embedded policy requirements with externally defined attribute rules, OpenTDF achieves a powerful and flexible ABAC implementation for data-centric security.

# Security | OpenTDF
OpenTDF Security Concepts
-------------------------

OpenTDF is designed with security and tamper evidence as core principles, enabling data-centric protection where security travels with the data itself. This document outlines the key conceptual mechanisms that provide these guarantees.

The most fundamental layer of protection is **payload encryption**. The original data within a TDF is encrypted using strong, authenticated symmetric encryption algorithms (typically AES-256-GCM). This ensures the confidentiality of the data – it cannot be read without the correct decryption key. The management and protection of this decryption key are handled by other mechanisms described below.

While encryption protects confidentiality, it doesn't inherently prevent undetected modification of the _ciphertext_. An attacker could potentially flip bits in the encrypted data. OpenTDF addresses this using the **`integrityInformation`** object within the manifest.

*   **Purpose:** To allow recipients to verify that the encrypted payload has not been altered since its creation. This is especially critical for streamed data.
*   **Mechanism:**
    1.  **Segmentation:** The plaintext payload is processed in chunks (segments).
    2.  **Segment Hashing/Tagging:** As each segment is encrypted (using AES-GCM, for example), a cryptographic integrity tag (like a GMAC) is generated for that encrypted segment using the _payload encryption key_. This tag is stored (as `hash`) in the corresponding [Segment Object](about:/spec/schema/opentdf/integrity_information#encryptioninformationintegrityinformationsegment).
    3.  **Root Signature:** All the individual segment tags/hashes are concatenated in order. A final HMAC (e.g., HMAC-SHA256) is calculated over this concatenated string of hashes, again using the _payload encryption key_. This result is stored as the `rootSignature.sig`.
*   **Result:** Any modification to even a single bit of the encrypted payload will invalidate the integrity tag of the affected segment _and_ consequently invalidate the final `rootSignature`. During decryption, the receiving client MUST verify the integrity tag of each segment and the overall `rootSignature`. Failure indicates tampering.

It's crucial that the access policy defined for a TDF cannot be detached from the key required to decrypt it. An attacker shouldn't be able to take a wrapped key associated with a strict policy and attach it to a TDF manifest that specifies a weaker policy. The **`policyBinding`** object within _each_ [Key Access Object](https://opentdf.io/spec/schema/opentdf/key_access_object) prevents this.

*   **Purpose:** To cryptographically link the specific access policy (defined in `encryptionInformation.policy`) to a particular wrapped key share held by a specific Key Access Server (KAS).
*   **Mechanism:**
    1.  The client retrieves the full, Base64-encoded `policy` string from the `encryptionInformation` section of the manifest it is constructing.
    2.  For _each_ key share it prepares to wrap for a specific KAS, the client takes the _plaintext key share_ itself.
    3.  It calculates an HMAC (e.g., HMAC-SHA256, specified by `policyBinding.alg`) using the **plaintext key share** as the secret key and the **Base64-encoded policy string** as the message data.
    4.  This resulting HMAC hash is Base64 encoded and stored as `policyBinding.hash` within the _same_ `keyAccess` object that contains the corresponding wrapped key share.
*   **Result:** When a recipient requests key access from a KAS, they provide the `keyAccess` object (including the `policyBinding`). The KAS decrypts the `wrappedKey` to get the plaintext key share. It then _recalculates_ the policy binding HMAC using this key share and the policy string provided (or referenced) in the request. If the calculated hash matches the `policyBinding.hash` received from the client, the KAS knows the policy presented corresponds to the one originally bound to this key share. If they don't match, it indicates tampering or a mismatch, and the KAS MUST deny the request.

To enhance security and enable multi-party control, OpenTDF supports **key splitting**. Instead of a single KAS holding the complete (wrapped) key, the key can be divided into multiple shares distributed across different KAS instances.

*   **Purpose:** To require authorization from multiple, independent KAS entities before a client can reconstruct the full payload decryption key. This prevents a single compromised KAS from leaking the key and enforces multi-party access control logic.
*   **Mechanism:**
    1.  The client generates the payload encryption key.
    2.  It splits the key into multiple cryptographic shares (e.g., using XOR with random nonces such that `Share1 ⊕ Share2 ⊕ ... ⊕ ShareN = FullKey`).
    3.  Each share is treated as an independent key: it's wrapped using the public key of its designated KAS and associated with its own [Policy Binding](#policy-binding).
    4.  Each wrapped share is stored in a separate [Key Access Object](https://opentdf.io/spec/schema/opentdf/key_access_object) within the `encryptionInformation.keyAccess` array. Crucially, each of these objects is assigned a unique **Split ID** (`sid`).
    5.  To decrypt, a client must contact _each_ KAS responsible for a required share (identified via the `sid` and `url`).
    6.  Each KAS independently verifies the request against its bound policy (using the [Policy Binding](#policy-binding)).
    7.  If all necessary KASes grant access, the client receives the unwrapped _shares_.
    8.  The client reconstructs the full payload key by combining the shares (e.g., XORing them together).
*   **Result:** Access requires successfully authenticating and satisfying the policy constraints at _multiple_ independent KAS instances. No single KAS holds enough information to decrypt the data alone.

These mechanisms work together:

*   **Encryption** protects confidentiality.
*   **Payload Integrity** ensures the encrypted data hasn't been undetectably modified.
*   **Policy Binding** ensures the access policy cannot be decoupled from the key access grant for a specific KAS.
*   **Key Splitting** enforces multi-party authorization, preventing single points of failure or compromise for key access.

This layered approach provides robust, data-centric security and tamper evidence for data protected by OpenTDF.

# Protocol | OpenTDF
OpenTDF Protocols
-----------------

This section describes the interaction protocols between OpenTDF clients (SDKs) and Key Access Servers (KAS) for securely managing access to the Data Encryption Keys (DEKs) used to protect TDF payloads.

A core design principle of OpenTDF is **crypto-agility**. The specific cryptographic algorithms and protocols used for key wrapping and KAS communication are not rigidly fixed by the core TDF structure. Instead, each [Key Access Object](https://opentdf.io/spec/schema/opentdf/key_access_object) within a TDF's manifest specifies:

1.  The **URL** of the responsible KAS.
2.  The **protocol** identifier (e.g., `wrapped`) indicating how to interact with that KAS.
3.  A **Key Identifier (`kid`)** referencing a specific KAS public key.
4.  A **Split Identifier (`sid`)** uniquely identifying a key share when the DEK is split across multiple KAS instances for multi-party access control

This allows different `keyAccess` objects within the _same_ TDF to potentially use different key wrapping mechanisms (e.g., one KAS using RSA, another using ECIES based on Elliptic Curve Cryptography) or evolve independently to adopt new algorithms, such as post-quantum cryptography, without breaking the overall TDF format.

The client SDK MUST interpret the details within a specific `keyAccess` object to determine how to interact with the corresponding KAS.

While specific protocols vary, the high-level interaction generally follows these phases:

1.  **TDF Creation:** The SDK encrypts the payload with a generated DEK, defines the access policy, wraps the DEK using the target KAS's public key(s) according to the chosen protocol(s), calculates policy bindings, and constructs the manifest.
2.  **Access Request:** A client SDK parses the TDF manifest, identifies the relevant `keyAccess` object(s), and sends a request to the specified KAS URL(s). This request includes the wrapped key(s), policy binding information, the policy itself, and client authentication/authorization context (including the client's public key for rewrapping).
3.  **KAS Verification:** The KAS authenticates the client, decrypts the wrapped DEK share(s) using its private key, validates the policy binding against the provided policy and the decrypted DEK share, and performs the authorization check (evaluating the policy against the client's authenticated attributes).
4.  **Key Rewrap & Response:** If all checks pass, the KAS re-encrypts ("rewraps") the DEK share using the client's public key provided in the request and returns it. If any check fails, the KAS returns an error.
5.  **Payload Decryption:** The client SDK decrypts the rewrapped DEK share(s) using its private key, reconstructs the full DEK (if key splitting was used), and uses the DEK to decrypt the TDF payload, verifying payload integrity simultaneously.

The [OpenTDF reference implementation (opentdf/platform)](https://github.com/opentdf/platform) demonstrates specific protocols. Below is a detailed example flow using **RSA** for wrapping the DEK. This assumes a scenario with a single KAS for simplicity.

### TDF Creation (Encryption Flow)
[​](#tdf-creation-encryption-flow "Direct link to TDF Creation (Encryption Flow)")

_Executed by the OpenTDF Client/SDK_

1.  **Generate DEK:** Generate a cryptographically strong symmetric Data Encryption Key (DEK) (e.g., AES-256).
2.  **Encrypt Payload:** Encrypt the original payload data using the DEK and an authenticated encryption mode (e.g., AES-256-GCM), generating an Initialization Vector (IV) and integrity tags per segment. Store the IV and segment information.
3.  **Define Policy:** Construct the [Policy Object](https://opentdf.io/spec/schema/opentdf/policy) JSON defining the required attributes (`dataAttributes`) and dissemination list (`dissem`). Base64 encode this JSON string.
4.  **Generate Policy Binding:** Calculate the policy binding hash: `HMAC(DEK, Base64(policyJSON))` using a standard algorithm like HMAC-SHA256. Base64 encode the resulting hash.
5.  **Prepare Optional Metadata:** If client-specific metadata needs to be passed securely to the KAS during decryption, prepare this data.
6.  **Encrypt Optional Metadata:** Encrypt the prepared metadata using the DEK (e.g., AES-GCM). Base64 encode the ciphertext. The encypted metadata is always passed to the KAS for processing, but from the perspective of a developer using the SDK, it is optional.
7.  **Fetch KAS Public Key:** Obtain the target KAS's RSA public key (identified by the KAS URL and potentially a `kid`). This might involve a separate discovery step or be pre-configured.
8.  **Wrap DEK:** Encrypt the plaintext DEK using the KAS's RSA public key (e.g., using RSAES-OAEP). Base64 encode the resulting ciphertext.
9.  **Construct Key Access Object:** Create the [Key Access Object](https://opentdf.io/spec/schema/opentdf/key_access_object) including:
    *   `type`: "wrapped"
    *   `url`: KAS URL
    *   `protocol`: "kas" (or a more specific identifier if needed)
    *   `kid`: Identifier of the KAS key used.
    *   `wrappedKey`: Base64 encoded wrapped DEK from step 8.
    *   `policyBinding`: Object containing `alg` (e.g., "HS256") and the Base64 encoded `hash` from step 4.
    *   `encryptedMetadata`: (Optional) Base64 encoded encrypted metadata from step 6.
10.  **Construct Manifest:** Assemble the full `manifest.json` including the `payload`, `encryptionInformation` (containing the `keyAccess` object(s), `method`, `integrityInformation`, and `policy` string), and any `assertions`.
11.  **Package TDF:** Create the Zip archive containing `manifest.json` and the encrypted payload file.
12.  **Securely Discard DEK:** Erase the plaintext DEK from memory immediately after it has been wrapped and used for metadata encryption/bindings. It should _never_ be stored persistently by the encrypting client.

### TDF Access (Decryption Flow)
[​](#tdf-access-decryption-flow "Direct link to TDF Access (Decryption Flow)")

_Involves interaction between Client/SDK and KAS_

**Phase 1: Client Preparation & Request** _(Executed by SDK)_

1.  **Parse Manifest:** Read the TDF's `manifest.json`.
2.  **Identify KAS Target(s):** Select the appropriate [Key Access Object](https://opentdf.io/spec/schema/opentdf/key_access_object)(s) based on desired KAS or required key shares (`sid` if splitting).
3.  **Extract Information:** From the selected `keyAccess` object(s), extract the KAS `url`, `wrappedKey`, `policyBinding` object, and optionally `encryptedMetadata`. Extract the Base64 `policy` string from `encryptionInformation`.
4.  **Prepare Client Context:** Obtain the client's authentication credentials (e.g., OAuth token) and the client's public key (corresponding to the private key the client will use for decryption).
5.  **Construct Rewrap Request:** Create a request payload (typically JSON) containing:
    *   The `wrappedKey` to be rewrapped.
    *   The `policyBinding` object (`alg` and `hash`).
    *   The Base64 `policy` string.
    *   (Optional) The `encryptedMetadata`.
    *   The client's public key (for the KAS to rewrap the DEK).
    *   Client authentication/authorization information (e.g., in HTTP headers).
6.  **Send Request:** POST the request payload to the KAS endpoint (e.g., `{KAS_URL}/v1/rewrap`).

**Phase 2: KAS Processing & Verification** _(Executed by KAS)_

7.  **Authenticate Client:** Verify the client's authentication credentials. If invalid, return an authentication error.
8.  **Decrypt DEK Share:** Use the KAS's _private_ RSA key (corresponding to the public key used for wrapping, identified by `kid`) to decrypt the `wrappedKey` provided in the request, yielding the plaintext DEK share.
9.  **Validate Policy Binding:**
    *   Recalculate the HMAC: `HMAC(DEK share, policy string from request)` using the algorithm specified in the request's `policyBinding.alg`.
    *   Compare the recalculated HMAC hash with the `policyBinding.hash` provided in the request.
    *   If they do not match, return a policy binding error (indicates tampering or mismatch).
10.  **(Optional) Decrypt Metadata:** If `encryptedMetadata` was provided, decrypt it using the plaintext DEK share. This metadata might inform policy decisions or logging.
11.  **Perform Authorization Check:**
     *   Retrieve the requesting client's validated attributes/entitlements (based on their authenticated identity).
     *   Parse the `policy` string from the request to get the required `dataAttributes` and `dissem` list.
     *   Evaluate the policy rules (potentially retrieving external Attribute Definitions) against the client's attributes.
     *   Check if the client is in the `dissem` list (if applicable).
     *   If authorization fails (policy requirements not met), return an authorization error.
12.  **Rewrap DEK Share:** If all checks pass, encrypt the plaintext DEK share using the client's public key provided in the request (e.g., using RSAES-OAEP if the client key is RSA). Base64 encode the result.
13.  **Send Response:** Return a success response containing the Base64 encoded, rewrapped DEK share.

**Phase 3: Client Decryption** _(Executed by SDK)_

14.  **Receive Response:** Get the response from the KAS. Check for errors (authentication, binding, authorization failures).
15.  **Decrypt DEK Share:** If the request was successful, use the client's _private_ key to decrypt the rewrapped DEK share received from the KAS.
16.  **(If Key Splitting) Reconstruct DEK:** If multiple shares were required (`sid` was used), combine the decrypted shares (e.g., via XOR) to reconstruct the full plaintext DEK.
17.  **Decrypt Payload:** Use the plaintext DEK and the parameters from `encryptionInformation.method` (IV) to decrypt the TDF payload. During decryption (especially with AES-GCM or streaming), simultaneously verify the integrity of each segment using the `hash` from the [Segment Object](https://opentdf.io/spec/schema/opentdf/integrity_information) and finally verify the `rootSignature` from [`integrityInformation`](https://opentdf.io/spec/schema/opentdf/integrity_information). If any integrity check fails, abort decryption and report an error.
18.  **Securely Discard DEK:** Once the payload is decrypted or decryption fails, securely erase the plaintext DEK and any intermediate shares from memory.

KAS implementations SHOULD return standard HTTP error codes and informative error messages (without revealing sensitive internal state) for failed requests, clearly distinguishing between:

*   Authentication failures (401/403)
*   Policy Binding validation failures (e.g., 400 Bad Request or 403 Forbidden)
*   Authorization failures (policy denied) (403 Forbidden)
*   Invalid input or malformed requests (400 Bad Request)
*   Internal server errors (500)

Clients MUST handle these errors appropriately.

# OpenTDF
OpenTDF Specification Overview
------------------------------

This section details the **OpenTDF** format, the primary specification for general-purpose Trusted Data Format (TDF) implementations. It utilizes a JSON-based manifest packaged with the encrypted payload within a standard Zip archive.

Before diving into specific object definitions, understand these core OpenTDF concepts:

*   **Security:** Learn about what makes OpenTDF secure. See [Security Concepts](https://opentdf.io/spec/concepts/security).
*   **Key Access and Wrapping:** How access control is defined using ABAC. See [Access Control](https://opentdf.io/spec/concepts/access_control).

An OpenTDF file is a Zip archive, typically using the `.tdf` extension (e.g., `document.pdf.tdf`). It MUST contain the following components:

1.  **`manifest.json`:** A JSON file containing all metadata required for decryption and access control. This is the core of the TDF structure.
2.  **`payload`:** The encrypted original data. The filename within the archive is referenced by the `manifest.json` (commonly `0.payload`).

![img](data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MDAgMjgwIj4KICA8IS0tIE1haW4gY29udGFpbmVyIC0tPgogIDxyZWN0IHg9IjUwIiB5PSIzMCIgd2lkdGg9IjMwMCIgaGVpZ2h0PSIyMjAiIHJ4PSI1IiByeT0iNSIgZmlsbD0iI2YwZjBmMCIgc3Ryb2tlPSIjMzMzIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSIyMDAiIHk9IjU1IiBmb250LWZhbWlseT0iQXJpYWwsIHNhbnMtc2VyaWYiIGZvbnQtc2l6ZT0iMTYiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZpbGw9IiMzMzMiPm15X2RvY3VtZW50LmV4dC50ZGYgKFppcCk8L3RleHQ+CiAgCiAgPCEtLSBtYW5pZmVzdC5qc29uIC0tPgogIDxyZWN0IHg9IjcwIiB5PSI4MCIgd2lkdGg9IjI2MCIgaGVpZ2h0PSI1MCIgcng9IjMiIHJ5PSIzIiBmaWxsPSIjZmZmZmZmIiBzdHJva2U9IiM2NjYiIHN0cm9rZS13aWR0aD0iMS41Ii8+CiAgPHRleHQgeD0iMjAwIiB5PSIxMTAiIGZvbnQtZmFtaWx5PSJBcmlhbCwgc2Fucy1zZXJpZiIgZm9udC1zaXplPSIxNCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iIzMzMyI+bWFuaWZlc3QuanNvbjwvdGV4dD4KICAKICA8IS0tIDAucGF5bG9hZCAtLT4KICA8cmVjdCB4PSI3MCIgeT0iMTUwIiB3aWR0aD0iMjYwIiBoZWlnaHQ9IjUwIiByeD0iMyIgcnk9IjMiIGZpbGw9IiNmZmZmZmYiIHN0cm9rZT0iIzY2NiIgc3Ryb2tlLXdpZHRoPSIxLjUiLz4KICA8dGV4dCB4PSIyMDAiIHk9IjE4MCIgZm9udC1mYW1pbHk9IkFyaWFsLCBzYW5zLXNlcmlmIiBmb250LXNpemU9IjE0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmaWxsPSIjMzMzIj4wLnBheWxvYWQgKEVuY3J5cHRlZCk8L3RleHQ+Cjwvc3ZnPg==)

The `manifest.json` file orchestrates the TDF. Its main sections are:

*   **Payload Description:** Information about the encrypted payload (type, reference, protocol, encryption status). See [Payload Object](https://opentdf.io/spec/schema/opentdf/payload).
*   **Encryption Information:** Details on how the payload was encrypted, how to access the key, integrity checks, and the access policy. See [Encryption Information](https://opentdf.io/spec/schema/opentdf/encryption_information). This includes:
    *   [Key Access Objects](https://opentdf.io/spec/schema/opentdf/key_access_object): How and where to get the decryption key.
    *   [Method](https://opentdf.io/spec/schema/opentdf/method): Symmetric encryption algorithm details.
    *   [Integrity Information](https://opentdf.io/spec/schema/opentdf/integrity_information): Hashes/signatures for payload integrity.
    *   [Policy](https://opentdf.io/spec/schema/opentdf/policy): The access control policy (embedded as a Base64 string).
*   **Assertions:** Optional, verifiable statements about the TDF or payload. See [Assertions](https://opentdf.io/spec/schema/opentdf/assertion).

Use the links below to explore the detailed structure of each component:

*   [**Manifest Structure (`manifest.json`)**](https://opentdf.io/spec/schema/opentdf/manifest)
*   [Payload Object](https://opentdf.io/spec/schema/opentdf/payload)
*   [Encryption Information Object](https://opentdf.io/spec/schema/opentdf/encryption_information)
    *   [Key Access Object](https://opentdf.io/spec/schema/opentdf/key_access_object)
    *   [Method Object](https://opentdf.io/spec/schema/opentdf/method)
    *   [Integrity Information Object](https://opentdf.io/spec/schema/opentdf/integrity_information)
    *   [Segment Object](https://opentdf.io/spec/schema/opentdf/integrity_information)
*   [Assertions](https://opentdf.io/spec/schema/opentdf/assertion)
    *   [Statement Object](https://opentdf.io/spec/schema/opentdf/assertion_statement)
    *   [Binding Object](https://opentdf.io/spec/schema/opentdf/assertion_binding)
*   [**Conceptual Guides:**](https://opentdf.io/spec/schema/)
    *   [Security](https://opentdf.io/spec/concepts/security)
    *   [Access Control](https://opentdf.io/spec/concepts/access_control)

# Manifest | OpenTDF
The `manifest.json` file MUST be in JSON format and reside within the root of the OpenTDF Zip archive. It serves as the central metadata component, storing the necessary information for processing the TDF payload and making access decisions by a Policy Enforcement Point (PEP).

This example illustrates a complete `manifest.json` structure. Links point to detailed descriptions of each major section.

```
{
  "tdf_spec_version": "1.0.0",
  // --- Payload Object ---
  "payload": {
    "type": "reference",
    "url": "0.payload",
    "protocol": "zip",
    "isEncrypted": true,
    "mimeType": "application/octet-stream"
  },
  // --- Encryption Information Object ---
  "encryptionInformation": {
    "type": "split",
    // --- Key Access Array ---
    "keyAccess": [
      {
        "type": "wrapped",
        "url": "http://kas.example.com:4000",
        "protocol": "kas",
        "wrappedKey": "YBkqvsiDnyDfw5JQzux2S2IaiClhsojZuLYY9WOc9N9l37A5/Zi7iloxcqgFvBFbzVjGW4QBwAHsytKQvE87bHTuQkZs4XyPACOZE/k9r+mK8KazcGTkOnqPKQNhf2XK4TBACJZ6eItO5Q1eHUQVLKjxUfgyx2TBDfhB/7XifNthu+6lFbKHmPl1q7q1Vaa/rpPRhSgqf89x5fQvcSWdkuOH9Y4wTa8tdKqSS3DUNMKTIUQq8Ti/WFrq26DRemybBgBcL/CyUZ98hFjDQgy4csBusEqwQ5zG+UAoRgkLkHiAw7hNAayAUCVRw6aUYRF4LWfcs2BM9k6d3bHqun0v5w==",
        "policyBinding": {
          "alg": "HS256",
          "hash": "ZGMwNGExZjg0ODFjNDEzZTk5NjdkZmI5MWFjN2Y1MzI0MTliNjM5MmRlMTlhYWM0NjNjN2VjYTVkOTJlODcwNA=="
        },
        "encryptedMetadata": "OEOqJCS6mZsmLWJ38lh6EN2lDUA8OagL/OxQRQ=="
      }
    ],
    // --- Method Object ---
    "method": {
      "algorithm": "AES-256-GCM",
      "isStreamable": true,
      "iv": "OEOqJCS6mZsmLWJ3"
    },
    // --- Integrity Information Object ---
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "YjliMzAyNjg4NzA0NzUyYmUwNzY1YWE4MWNhNDRmMDZjZDU3OWMyYTMzNjNlNDYyNTM4MDA4YjQxYTdmZmFmOA=="
      },
      "segmentSizeDefault": 1000000,
      "segmentHashAlg": "GMAC",
      // --- Segments Array ---
      "segments": [
        {
          "hash": "ZmQyYjY2ZDgxY2IzNGNmZTI3ODFhYTk2ZjJhNWNjODA=",
          "segmentSize": 14056,
          "encryptedSegmentSize": 14084
        }
      ],
      "encryptedSegmentSizeDefault": 1000028
    },
    // --- Policy String ---
    "policy": "eyJ1dWlkIjoiNjEzMzM0NjYtNGYwYS00YTEyLTk1ZmItYjZkOGJkMGI4YjI2IiwiYm9keSI6eyJhdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbInVzZXJAdmlydHJ1LmNvbSJdfX0="
  },
  // --- Assertions Array ---
  "assertions": [
      {
        "id": "nato-label-1",
        "type": "handling",
        "scope": "payload",
        "appliesToState": "encrypted",
        // --- Statement Object ---
        "statement": {
            "format": "json-structured",
            "schema": "urn:nato:stanag:4774:confidentialitymetadatalabel:1:0",
            "value": {
              "Xmlns": "urn:nato:stanag:4774:confidentialitymetadatalabel:1:0",
              "CreationTime": "2015-08-29T16:15:00Z",
              "ConfidentialityInformation": {
                  "PolicyIdentifier": "NATO",
                  "Classification": "SECRET",
                  "Category": { "Type": "PERMISSIVE", "TagName": "Releasable to", "GenericValues": [ "SWE", "FIN", "FRA" ] }
              }
          }
        },
        // --- Binding Object ---
        "binding": {
          "method": "jws",
          "signature": "eyJhbGciOiJIUzI1NiJ9.eyJzY2hlbWEiOiJ1cm46bmF0bzpzdGFuYWc6NDc3NDpjb25maWRlbnRpYWxpdHltZXRhZGF0YWxhYmVsOjE6MCIsImZvcm1hdCI6Impzb24tc3RydWN0dXJlZCIsInZhbHVlIjp7IlhtbG5zIjoidXJuOm5hdG86c3RhbmFnOjQ3NzQ6Y29uZmlkZW50aWFsaXR5bWV0YWRhdGFsYWJlbDoxOjAiLCJDcmVhdGlvblRpbWUiOiIyMDE1LTA4LTI5VDE2OjE1OjAwWiIsIkNvbmZpZGVudGlhbGl0eUluZm9ybWF0aW9uIjp7IlBvbGljeUlkZW50aWZpZXIiOiJOQVRPIiwiQ2xhc3NpZmljYXRpb24iOiJTRUNSRVQiLCJDYXRlZ29yeSI6eyJNeXBlIjoiUEVSTUlTU0lWRSIsIlRhZ05hbWUiOiJSZWxlYXNhYmxlIHRvIiwiR2VuZXJpY1ZhbHVlcyI6WyJTV0UiLCJGSU4iLCJGUkEiXX19fX0.FakeBindingSignatureExample"
        }
      }
  ]
}

```


# Payload | OpenTDF
Payload Object
--------------

The `payload` object within the [manifest](https://opentdf.io/spec/schema/opentdf/manifest) contains metadata required to locate and process the TDF's encrypted payload.

Example[​](#example "Direct link to Example")
---------------------------------------------

```
"payload": {
    "type": "reference",
    "url": "0.payload",
    "protocol": "zip",
    "isEncrypted": true,
    "mimeType": "application/pdf"
}

```


Fields[​](#fields "Direct link to Fields")
------------------------------------------



* Parameter: type
  * Type: String
  * Description: Describes how the payload is referenced. Currently, reference (indicating the payload is within the TDF archive) is the only specified type.
  * Required?: Yes
* Parameter: url
  * Type: String
  * Description: A URI pointing to the location of the payload. For type: reference, this is typically a relative path within the Zip archive (e.g., 0.payload).
  * Required?: Yes
* Parameter: protocol
  * Type: String
  * Description: Designates the packaging format of the payload within the TDF. Allowed values include zip (for standard files) and zipstream (for streamed files).
  * Required?: Yes
* Parameter: isEncrypted
  * Type: Boolean
  * Description: Indicates whether the payload referenced by url is encrypted. MUST be true for standard TDFs. Future use may allow false.
  * Required?: Yes
* Parameter: mimeType
  * Type: String
  * Description: Specifies the MIME type of the original, unencrypted data. If not provided, application/octet-stream SHOULD be assumed.
  * Required?: No


# Encryption Information | OpenTDF
The `encryptionInformation` object, part of the [manifest](https://opentdf.io/spec/schema/opentdf/manifest), aggregates all information related to the encryption of the payload, policy enforcement, and key management.

Example[​](#example "Direct link to Example")
---------------------------------------------

```
"encryptionInformation": {
    "type": "split",
    "keyAccess": [ { /* See Key Access Object */ } ],
    "method": { /* See Method Object */ },
    "integrityInformation": { /* See Integrity Information Object */ },
    "policy": "eyJ1dWlkIjoiNGYw...vbSJdfX0=" // Base64 encoded Policy Object JSON
}

```


Fields[​](#fields "Direct link to Fields")
------------------------------------------



* Parameter: type
  * Type: String
  * Description: Specifies the key management scheme. split is the primary scheme, allowing key sharing or splitting across multiple keyAccess entries.
  * Required?: Yes
* Parameter: keyAccess
  * Type: Array
  * Description: An array of one or more Key Access Objects. Each object describes how to obtain the payload decryption key (or a key split) from a specific Key Access Server (KAS).
  * Required?: Yes
* Parameter: method
  * Type: Object
  * Description: Describes the symmetric encryption algorithm used on the payload. See Method Object.
  * Required?: Yes
* Parameter: integrityInformation
  * Type: Object
  * Description: Contains information for verifying the integrity of the payload, especially for streamed TDFs. See Integrity Information Object.
  * Required?: Yes
* Parameter: policy
  * Type: String
  * Description: A Base64 encoding of the JSON string representing the Policy Object. Defines the access control rules for the TDF. For conceptual details, see Access Control.
  * Required?: 


# Key Access Object | OpenTDF
A Key Access Object, found within the `keyAccess` array in [`encryptionInformation`](https://opentdf.io/spec/schema/opentdf/encryption_information), stores information about how a specific payload encryption key (or key split/share) is stored and accessed, typically via a Key Access Server (KAS).

```
{
  "type": "wrapped",
  "url": "https://kas.example.com:5000",
  "kid": "6f3b6a82-2f30-4c8a-aef3-57c65b8e7387", // Optional KAS Key ID
  "sid": "split-id-1", // Optional Split ID
  "protocol": "kas",
  "wrappedKey": "OqnOE...B82uw==", // Base64 encoded wrapped key
  "policyBinding": {
    "alg": "HS256",
    "hash": "BzmgoIxZzMmIF42qzbdD4Rw30GtdaRSQL2Xlfms1OPs=" // Base64 encoded hash
  },
  "encryptedMetadata": "ZoJTNW24UMhnXIif0mSnqLVCU=" // Base64 encoded encrypted metadata
}

```


This nested object provides the cryptographic binding between the policy and the key share.

# Method | OpenTDF
Method Object
-------------

The `method` object, nested within [`encryptionInformation`](https://opentdf.io/spec/schema/opentdf/encryption_information), describes the symmetric encryption algorithm and parameters used to encrypt the payload.

Example[​](#example "Direct link to Example")
---------------------------------------------

```
"method": {
  "algorithm": "AES-256-GCM",
  "isStreamable": true,
  "iv": "D6s7cSgFXzhVkran" // Base64 encoded IV
}

```


Fields[​](#fields "Direct link to Fields")
------------------------------------------



* Parameter: algorithm
  * Type: String
  * Description: The symmetric encryption algorithm used. AES-256-GCM is the recommended and commonly implemented algorithm.
  * Required?: Yes
* Parameter: isStreamable
  * Type: Boolean
  * Description: Indicates if the payload was encrypted in segments suitable for streaming decryption. If true, integrityInformation MUST contain segment details.
  * Required?: Yes
* Parameter: iv
  * Type: String
  * Description: The Base64 encoded Initialization Vector (IV) used with the symmetric algorithm. MUST be unique for each TDF encrypted with the same key. For AES-GCM, typically 12 bytes (96 bits).
  * Required?: Yes


# Integrity Information | OpenTDF
The `integrityInformation` object, nested within [`encryptionInformation`](https://opentdf.io/spec/schema/opentdf/encryption_information), provides mechanisms to verify the integrity of the encrypted payload, essential for streaming and detecting tampering.

```
"integrityInformation": {
  "rootSignature": {
    "alg": "HS256",
    "sig": "M2E2MTI5YmMxMW...WNlMWVjYjlmODUzNmNiZQ==" // Base64 encoded signature
  },
  "segmentHashAlg": "GMAC",
  "segments": [ { /* See Segment Object */ } ],
  "segmentSizeDefault": 1000000,
  "encryptedSegmentSizeDefault": 1000028
}

```


Object containing integrity information about a segment of the payload, including its hash.

# Policy | OpenTDF
Policy Object (Structure)
-------------------------

This document describes the JSON structure of the Policy Object. The entire object is JSON stringified and then Base64 encoded when stored in the `encryptionInformation.policy` field of the [manifest](https://opentdf.io/spec/schema/opentdf/manifest). For a conceptual overview, see [Access Control Concepts](https://opentdf.io/spec/concepts/access_control).

The Policy Object contains the access control rules for the TDF.

Example (Decoded JSON Structure)
[​](#example-decoded-json-structure "Direct link to Example (Decoded JSON Structure)")
----------------------------------------------------------------------------------------------------------------------

```
{
"uuid": "1111-2222-33333-44444-abddef-timestamp",
"body": {
    "dataAttributes": [<Attribute Object>],
    "dissem": ["user-id@domain.com"]
  },
}

```


Fields[​](#fields "Direct link to Fields")
------------------------------------------



* Parameter: uuid
  * Type: String
  * Description: A UUID uniquely identifying this specific policy instance.
  * Required?: Yes
* Parameter: body
  * Type: Object
  * Description: Contains the core access control constraints.
  * Required?: Yes
* Parameter: body.dataAttributes
  * Type: Array
  * Description: An array of Attribute Objects. Represents the attributes an entity must possess (according to their definitions and rules) to satisfy the policy's ABAC requirements.
  * Required?: Yes
* Parameter: body.dissem
  * Type: Array
  * Description: An array of strings, where each string is a unique identifier for an entity (e.g., email address, user ID). If present, an entity requesting access must be included in this list in addition to satisfying the dataAttributes. If empty or omitted, any entity satisfying dataAttributes may be granted access.
  * Required?: No


# Attribute Object | OpenTDF
Attribute Object (Structure)
----------------------------

This document describes the JSON structure representing an Attribute Instance when embedded within a [Policy Object](https://opentdf.io/spec/schema/opentdf/policy). For a conceptual overview of attributes, and their role in access control, see [Access Control Concepts](https://opentdf.io/spec/concepts/access_control).

An Attribute Object represents a single required attribute instance needed to access the data.

Example[​](#example "Direct link to Example")
---------------------------------------------

```
{
  "attribute": "https://example.com/attr/classification/value/topsecret"
}

```


Fields[​](#fields "Direct link to Fields")
------------------------------------------



* Parameter: attribute
  * Type: String
  * Description: The full Attribute Instance URI, composed of {Namespace}/attr/{Name}/value/{Value}. See Access Control concepts.
  * Required?: 


# Assertion | OpenTDF
The `assertions` array, an optional top-level property in the [manifest](https://opentdf.io/spec/schema/opentdf/manifest), contains assertion objects. Assertions are verifiable statements about the TDF or its payload, often used for security labeling or handling instructions.

```
"assertions": [
  {
    "id": "handling-assertion-1",
    "type": "handling",
    "scope": "payload",
    "appliesToState": "encrypted",
    "statement": { /* See Statement Object */ },
    "binding": { /* See Binding Object */ }
  }
]

```


Each object within the assertions array represents a single assertion and has the following fields:

# Assertion Statement | OpenTDF
Statement Object
----------------

The `statement` object, nested within an [Assertion Object](https://opentdf.io/spec/schema/opentdf/assertion), contains the core information or claim of the assertion.

Example[​](#example "Direct link to Example")
---------------------------------------------

```
"statement": {
  "schema": "urn:nato:stanag:4774:confidentialitymetadatalabel:1:0",
  "format": "json-structured",
  "value": {
      "Xmlns": "urn:nato:stanag:4774:confidentialitymetadatalabel:1:0",
      "CreationTime": "2015-08-29T16:15:00Z",
      "ConfidentialityInformation": { /* ... specific assertion info ... */ }
  }
}

```


Fields[​](#fields "Direct link to Fields")
------------------------------------------



* Parameter: schema
  * Type: String
  * Description: An optional URI identifying the schema or standard that defines the structure and semantics of the value.
  * Required?: No
* Parameter: format
  * Type: String
  * Description: Describes how the value is encoded. Common values: json-structured (value is a JSON object), base64binary (value is Base64 encoded binary), string.
  * Required?: Yes
* Parameter: value
  * Type: Any
  * Description: The assertion content itself, formatted according to the format field. Can be a string, number, boolean, object, or array (if format is json-structured).
  * Required?: Yes


# Assertion Binding | OpenTDF
Binding Object (Assertion)
--------------------------

The `binding` object, nested within an [Assertion Object](https://opentdf.io/spec/schema/opentdf/assertion), contains a cryptographic signature binding the assertion to the TDF context, ensuring its integrity and preventing replay on other TDFs.

Example[​](#example "Direct link to Example")
---------------------------------------------

```
"binding": {
  "method": "jws",
  "signature": "eyJhbGciOiJSUzI1NiJ9..." // Base64URL encoded JWS string
}

```


Fields[​](#fields "Direct link to Fields")
------------------------------------------



* Parameter: method
  * Type: String
  * Description: The cryptographic method used for the signature. jws (JSON Web Signature) is commonly used, implying standard JWS processing rules apply.
  * Required?: Yes
* Parameter: signature
  * Type: String
  * Description: The Base64URL encoded signature value (e.g., a JWS Compact Serialization string). The signature calculation MUST include the assertion content and sufficient TDF context (like policy or key info hash) to prevent replay.
  * Required?: Yes
