# Micro Research Repository API

A sample REST API demonstrating Attribute-Based Access Control (ABAC) using the Stratium platform. This application showcases route protection, authorization, and department-based data access controls for managing research datasets.

## Features

- **OIDC Authentication**: Secure authentication via Keycloak
- **ABAC Authorization**: Fine-grained access control using Stratium Platform Service
- **Department-Based Access**: Users can only access datasets from their department
- **Role-Based Permissions**: Admin, Editor, and Viewer roles with different capabilities
- **RESTful API**: Clean REST API built with Gin framework
- **Search & Filter**: Full-text search and filtering capabilities for datasets

## Data Model

### User
- ID, Name, Email, Department, Title, Role
- Roles: `admin`, `editor`, `viewer`

### Dataset
- ID, Title, Description, Owner, Data URL, Department, Tags
- Linked to owner (User) with department-based access control

## Authorization Rules

1. **Dataset Owners**: Full read-write access to their own datasets
2. **Department Access**: Users can read datasets from their department
3. **Admin Access**: Admins have full access to all datasets
4. **Cross-Department**: Users cannot access datasets from other departments (unless admin)

## Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────────┐
│   Client    │─────▶│  API Server  │─────▶│   PostgreSQL    │
│  (Browser)  │      │  (Gin/Go)    │      │   (Datasets)    │
└─────────────┘      └──────────────┘      └─────────────────┘
                            │
                            │ OIDC Auth
                            ▼
                     ┌──────────────┐
                     │   Keycloak   │
                     └──────────────┘
                            │
                            │ ABAC
                            ▼
                     ┌──────────────┐
                     │   Platform   │
                     │   Service    │
                     └──────────────┘
```

## Prerequisites

- Docker and Docker Compose
- Stratium services running (Platform, Keycloak)
- Go 1.23+ (for local development)

## Quick Start

### 1. Start Stratium Services

First, ensure the main Stratium services are running:

```bash
cd /path/to/stratium
make docker-up
```

This will start:
- Keycloak (http://localhost:8080)
- Platform Service (localhost:50051)
- PostgreSQL, Redis, etc.

### 2. Start the Micro Research API

```bash
cd samples/web/api

# Start the API and its database
docker-compose up -d

# Check logs
docker-compose logs -f api
```

The API will be available at http://localhost:8080

### 3. Get an Access Token

To interact with the API, you need a JWT token from Keycloak:

```bash
# Using one of the seeded users
curl -X POST 'http://localhost:8080/realms/stratium/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password' \
  -d 'client_id=micro-research-api' \
  -d 'client_secret=micro-research-secret' \
  -d 'username=alice@example.com' \
  -d 'password=password'

# Extract the access_token from the response
export TOKEN="<your-access-token>"
```

## API Endpoints

### Health Check
```bash
GET /health
```

### Users

```bash
# Get current user info
GET /api/v1/users/me
Authorization: Bearer $TOKEN

# List all users (admin only)
GET /api/v1/users
Authorization: Bearer $TOKEN

# Get user by ID
GET /api/v1/users/:id
Authorization: Bearer $TOKEN

# Create user (admin only)
POST /api/v1/users
Authorization: Bearer $TOKEN
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "department": "engineering",
  "title": "Researcher",
  "role": "editor"
}

# Update user
PUT /api/v1/users/:id
Authorization: Bearer $TOKEN
Content-Type: application/json

{
  "title": "Senior Researcher"
}

# Delete user (admin only)
DELETE /api/v1/users/:id
Authorization: Bearer $TOKEN
```

### Datasets

```bash
# List datasets (filtered by department access)
GET /api/v1/datasets?limit=20&offset=0
Authorization: Bearer $TOKEN

# Search datasets
GET /api/v1/datasets/search?q=neural&department=engineering&tags=machine-learning
Authorization: Bearer $TOKEN

# Get dataset by ID (ABAC check)
GET /api/v1/datasets/:id
Authorization: Bearer $TOKEN

# Create dataset
POST /api/v1/datasets
Authorization: Bearer $TOKEN
Content-Type: application/json

{
  "title": "My Research Data",
  "description": "Dataset containing experimental results",
  "data_url": "https://storage.example.com/my-data.zip",
  "department": "engineering",
  "tags": ["experiment", "results"]
}

# Update dataset (owner or admin only)
PUT /api/v1/datasets/:id
Authorization: Bearer $TOKEN
Content-Type: application/json

{
  "description": "Updated description",
  "tags": ["experiment", "results", "validated"]
}

# Delete dataset (owner or admin only)
DELETE /api/v1/datasets/:id
Authorization: Bearer $TOKEN
```

## Sample Data

The database is seeded with sample users and datasets:

### Users
- **Alice Johnson** (alice@example.com) - Engineering, Editor
- **Bob Smith** (bob@example.com) - Engineering, Viewer
- **Carol Davis** (carol@example.com) - Biology, Editor
- **David Wilson** (david@example.com) - Biology, Viewer
- **Eve Martinez** (eve@example.com) - Engineering, Admin

### Datasets
- Neural Network Training Data (Engineering - Alice)
- Sensor Telemetry 2024 (Engineering - Alice)
- Genomic Sequences Collection (Biology - Carol)
- Protein Structure Database (Biology - Carol)

## Development

### Local Development (without Docker)

```bash
# Install dependencies
cd samples/web/api
go mod download

# Set environment variables
export DATABASE_URL="postgres://research:research_password@localhost:5433/micro_research?sslmode=disable"
export PLATFORM_SERVICE_URL="localhost:50051"
export OIDC_ISSUER_URL="http://localhost:8080/realms/stratium"
export OIDC_CLIENT_ID="micro-research-api"
export OIDC_CLIENT_SECRET="micro-research-secret"
export PORT=":8888"

# Run the server
go run cmd/server/main.go
```

### Running Tests

```bash
# Unit tests
go test ./...

# Integration tests (requires services running)
go test -tags=integration ./...
```

## Configuration

Configuration is managed via environment variables:

| Variable | Default                                                                               | Description |
|----------|---------------------------------------------------------------------------------------|-------------|
| `PORT` | `:8888`                                                                               | API server port |
| `DATABASE_URL` | `postgres://research:research_password@localhost:5433/micro_research?sslmode=disable` | PostgreSQL connection string |
| `PLATFORM_SERVICE_URL` | `localhost:50051`                                                                     | Platform service gRPC address |
| `OIDC_ISSUER_URL` | `http://localhost:8080/realms/stratium`                                               | Keycloak realm URL |
| `OIDC_CLIENT_ID` | `micro-research-api`                                                                  | OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | `micro-research-secret`                                                               | OAuth2 client secret |

## Configuring ABAC Policies

The Micro Research API uses the Stratium Platform service for authorization decisions. To enforce department-based access control, you need to configure policies in the PAP (Policy Administration Point).

### PAP API Access

The PAP API is available at: `http://localhost:8090`

### Creating Department-Based Access Policies

#### Policy 1: Department Isolation for Read Access

This policy ensures users can only read datasets from their own department:

```bash
curl -X POST 'http://localhost:8090/api/v1/policies' \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "department-read-isolation",
  "description": "Users can only read datasets from their department",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.action == \"read\"\n    input.resource.resource_type == \"dataset\"\n    input.subject.department == input.resource.department\n}",
  "effect": "allow",
  "priority": 200,
  "enabled": true
}'
```

#### Policy 2: Owner-Based Write Access

This policy allows dataset owners to update and delete their own datasets:

```bash
curl -X POST 'http://localhost:8090/api/v1/policies' \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "owner-write-access",
  "description": "Dataset owners can update and delete their datasets",
  "language": "opa",
  "policy_content": "package stratium.authz\n\nimport future.keywords.in\n\ndefault allow = false\n\nallow {\n    input.action in [\"update\", \"delete\"]\n    input.resource.resource_type == \"dataset\"\n    input.resource.owner_id == input.subject.user_id\n}",
  "effect": "allow",
  "priority": 300,
  "enabled": true
}'
```

#### Policy 3: Admin Full Access

This policy grants admins full access to all datasets across departments:

```bash
curl -X POST 'http://localhost:8090/api/v1/policies' \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "admin-full-access",
  "description": "Administrators have full access to all datasets",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.resource.resource_type == \"dataset\"\n    input.subject.role == \"admin\"\n}",
  "effect": "allow",
  "priority": 100,
  "enabled": true
}'
```

#### Policy 4: Same Department Editor Access

This policy allows editors to read and update datasets in their department:

```bash
curl -X POST 'http://localhost:8090/api/v1/policies' \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "department-editor-access",
  "description": "Editors can read and update datasets in their department",
  "language": "opa",
  "policy_content": "package stratium.authz\n\nimport future.keywords.in\n\ndefault allow = false\n\nallow {\n    input.action in [\"read\", \"update\"]\n    input.resource.resource_type == \"dataset\"\n    input.subject.department == input.resource.department\n    input.subject.role == \"editor\"\n}",
  "effect": "allow",
  "priority": 250,
  "enabled": true
}'
```

### Complete Policy Setup Script

Create all policies at once using this script:

```bash
#!/bin/bash

PAP_URL="http://localhost:8090/api/v1/policies"

echo "Creating ABAC policies for Micro Research API..."

# Policy 1: Admin Full Access (Highest Priority)
echo "1. Creating admin-full-access policy..."
curl -s -X POST "$PAP_URL" \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "admin-full-access",
  "description": "Administrators have full access to all datasets",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.resource.resource_type == \"dataset\"\n    input.subject.role == \"admin\"\n}",
  "effect": "allow",
  "priority": 100,
  "enabled": true
}' | jq .

# Policy 2: Department Read Isolation
echo "2. Creating department-read-isolation policy..."
curl -s -X POST "$PAP_URL" \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "department-read-isolation",
  "description": "Users can only read datasets from their department",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.action == \"read\"\n    input.resource.resource_type == \"dataset\"\n    input.subject.department == input.resource.department\n}",
  "effect": "allow",
  "priority": 200,
  "enabled": true
}' | jq .

# Policy 3: Department Editor Access
echo "3. Creating department-editor-access policy..."
curl -s -X POST "$PAP_URL" \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "department-editor-access",
  "description": "Editors can read and update datasets in their department",
  "language": "opa",
  "policy_content": "package stratium.authz\n\nimport future.keywords.in\n\ndefault allow = false\n\nallow {\n    input.action in [\"read\", \"update\"]\n    input.resource.resource_type == \"dataset\"\n    input.subject.department == input.resource.department\n    input.subject.role == \"editor\"\n}",
  "effect": "allow",
  "priority": 250,
  "enabled": true
}' | jq .

# Policy 4: Owner Write Access (Highest Priority for Ownership)
echo "4. Creating owner-write-access policy..."
curl -s -X POST "$PAP_URL" \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "owner-write-access",
  "description": "Dataset owners can update and delete their datasets",
  "language": "opa",
  "policy_content": "package stratium.authz\n\nimport future.keywords.in\n\ndefault allow = false\n\nallow {\n    input.action in [\"update\", \"delete\"]\n    input.resource.resource_type == \"dataset\"\n    input.resource.owner_id == input.subject.subject_id\n}",
  "effect": "allow",
  "priority": 300,
  "enabled": true
}' | jq .

echo ""
echo "Policies created successfully!"
echo ""
echo "To view all policies:"
echo "  curl http://localhost:8090/api/v1/policies | jq ."
```

Save this script as `setup-policies.sh` and run:

```bash
chmod +x setup-policies.sh
./setup-policies.sh
```

### Verifying Policy Configuration

After creating the policies, verify they are active:

```bash
# List all policies
curl http://localhost:8090/api/v1/policies | jq .

# Check a specific policy
curl http://localhost:8090/api/v1/policies/<policy-id> | jq .

# Test a policy decision
curl -X POST 'http://localhost:8090/api/v1/policies/test' \
  -H 'Content-Type: application/json' \
  -d '{
  "language": "opa",
  "policy_content": "...",
  "subject_attributes": {
    "subject_id": "alice-id",
    "department": "engineering",
    "role": "editor"
  },
  "resource_attributes": {
    "resource_type": "dataset",
    "department": "engineering",
    "owner_id": "alice-id"
  },
  "action": "read"
}'
```

### Understanding Policy Priority

Policies are evaluated based on priority (lower number = higher priority):

- **Priority 100**: Admin full access (evaluated first)
- **Priority 200**: Department read isolation
- **Priority 250**: Department editor access
- **Priority 300**: Owner write access (evaluated last)

When multiple policies match, the first matching policy at the highest priority determines the access decision.

### Advanced Policy Examples

For more advanced policy examples including:
- Time-based access control
- Multi-department access for specific roles
- Tag-based access control
- Hierarchical department access
- Conditional write access
- Approval-based access

See [docs/example-policies.md](docs/example-policies.md)

## ABAC Examples

### Example 1: Department-Based Access

Alice (engineering dept) tries to access Carol's dataset (biology dept):

```bash
# This will be DENIED (after policies are configured)
GET /api/v1/datasets/<carol-dataset-id>
Authorization: Bearer <alice-token>

Response: 403 Forbidden
{
  "error": "access denied",
  "reason": "Subject attributes do not satisfy resource requirements"
}
```

### Example 2: Owner Access

Alice updates her own dataset:

```bash
# This will be ALLOWED (owner-write-access policy)
PUT /api/v1/datasets/<alice-dataset-id>
Authorization: Bearer <alice-token>

Response: 200 OK
```

### Example 3: Admin Override

Eve (admin) accesses any dataset:

```bash
# This will be ALLOWED (admin-full-access policy)
GET /api/v1/datasets/<any-dataset-id>
Authorization: Bearer <eve-token>

Response: 200 OK
```

### Example 4: Same Department Read

Bob (engineering, viewer) reads Alice's dataset (engineering):

```bash
# This will be ALLOWED (department-read-isolation policy)
GET /api/v1/datasets/<alice-dataset-id>
Authorization: Bearer <bob-token>

Response: 200 OK
```

## Troubleshooting

### API returns 401 Unauthorized
- Ensure your JWT token is valid and not expired
- Check that Keycloak is running and accessible
- Verify the OIDC configuration matches Keycloak settings

### API returns 403 Forbidden
- Check ABAC rules in the Platform service
- Verify user department matches dataset department
- Ensure user has appropriate role (admin/editor/viewer)

### Database connection errors
- Verify PostgreSQL container is running: `docker ps`
- Check database credentials in docker-compose.yml
- Ensure migrations ran successfully: `docker logs micro-research-db`

### Platform service connection errors
- Verify Platform service is running: `docker ps | grep platform`
- Check network connectivity: `docker network inspect stratium-network`
- Verify PLATFORM_SERVICE_URL is correct

### Keycloak OIDC issuer mismatch errors

If you see an error like:
```
Failed to initialize auth middleware: failed to create OIDC provider: oidc: issuer did not match the issuer returned by provider, expected "http://keycloak:8080/realms/stratium" got "http://localhost:8080/realms/stratium"
```

This occurs because Keycloak advertises `http://localhost:8080` as its issuer URL, but the API service inside Docker tries to access it via the hostname `keycloak:8080`.

**Solution**: Update the `extra_hosts` configuration in `docker-compose.yml` to map `localhost` to the Keycloak container's IP address.

1. Find the Keycloak container's IP address:
   ```bash
   docker inspect stratium-keycloak --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
   ```

2. Update the `extra_hosts` section in `docker-compose.yml` under the `api` service:
   ```yaml
   api:
     # ... other configuration ...
     extra_hosts:
       # Map localhost to keycloak container IP for OIDC discovery
       # Replace 172.18.0.6 with the actual IP from step 1
       - "localhost:172.18.0.6"
   ```

3. Recreate the API container:
   ```bash
   docker-compose up -d api
   ```

**Note**: The Keycloak IP address may change when containers are recreated. If you restart all services or clear Docker volumes, you'll need to update the `extra_hosts` configuration with the new IP address.

## License

This is a sample application for demonstration purposes.