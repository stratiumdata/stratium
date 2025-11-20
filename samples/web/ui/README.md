# Stratium Research UI

A React-based web application demonstrating **Attribute-Based Access Control (ABAC)** using the Stratium platform service, Keycloak authentication, and department-scoped data access.

## Overview

This UI application provides a secure interface for managing research datasets with fine-grained access control. It integrates with:

- **Backend API**: `samples/web/api` - Go-based REST API
- **Keycloak**: Authentication and user identity (stratium realm)
- **Stratium Platform Service**: ABAC policy enforcement via gRPC

## Features

- **Keycloak Authentication**: Secure login via OpenID Connect (PKCE flow)
- **ABAC Entitlements**: UI elements conditionally rendered based on:
  - User role (admin, editor, viewer)
  - Department affiliation
  - Dataset ownership
  - Real-time ABAC decisions from platform service
- **Dataset Management**:
  - Browse datasets (filtered by department)
  - Search and filter capabilities
  - Create/edit datasets (editor/admin only)
  - Delete datasets (owner/admin only)
- **User Management**: Admin-only view of all users across departments
- **Responsive UI**: Built with Tailwind CSS

## Tech Stack

- **React 19** with TypeScript
- **Vite** - Fast build tool and dev server
- **React Router** - Client-side routing
- **TanStack Query** - Server state management
- **Keycloak JS** - Authentication client
- **Axios** - HTTP client
- **Tailwind CSS** - Utility-first CSS framework

## Prerequisites

1. **Node.js 20+** and npm
2. **Running Stratium infrastructure**:
   - Keycloak on port 8080 (stratium realm configured)
   - Backend API on port 8888 (`samples/web/api`)
   - Platform service on port 50051
3. **Keycloak UI client created** (see setup below)

## Quick Start

### 1. Install Dependencies

\`\`\`bash
cd samples/web/ui
npm install
\`\`\`

### 2. Configure Environment

Copy the example environment file and update if needed:

\`\`\`bash
cp .env.example .env
\`\`\`

Default configuration:
\`\`\`env
VITE_API_BASE_URL=http://localhost:8888
VITE_KEYCLOAK_URL=http://localhost:8080
VITE_KEYCLOAK_REALM=stratium
VITE_KEYCLOAK_CLIENT_ID=micro-research-ui
\`\`\`

### 3. Create Keycloak Client

The UI requires a **public client** in Keycloak (different from the API's confidential client):

\`\`\`bash
./create-keycloak-client.sh
\`\`\`

This creates a client with:
- Client ID: \`micro-research-ui\`
- Type: Public (SPA)
- Flow: Authorization Code with PKCE
- Redirect URIs: \`http://localhost:3000/*\`

### 4. Start Development Server

\`\`\`bash
npm run dev
\`\`\`

The application will be available at: **http://localhost:3000**

### 5. Login

Use one of the demo users from the backend:

| Email | Password | Department | Role | Access |
|-------|----------|------------|------|--------|
| alice@example.com | password | engineering | editor | Can read/edit engineering datasets |
| bob@example.com | password | engineering | viewer | Can read engineering datasets |
| carol@example.com | password | biology | editor | Can read/edit biology datasets |
| eve@example.com | password | engineering | admin | Full access to all datasets |

## ABAC Policy Enforcement

The UI implements client-side permission checks that mirror the backend ABAC policies:

### Permission Rules

1. **Admins**: Full access to everything
2. **Department Isolation**: Users can only view datasets in their department
3. **Editor Permissions**: Can create and edit datasets in their department
4. **Owner Permissions**: Dataset owners can delete their own datasets
5. **Viewer Permissions**: Read-only access to department datasets

### How It Works

\`\`\`typescript
// Frontend permission hook (usePermissions.ts)
const permissions = usePermissions(dataset);

// Conditionally render UI elements
{permissions.canEdit && (
  <button>Edit Dataset</button>
)}

{permissions.canDelete && (
  <button>Delete Dataset</button>
)}
\`\`\`

The frontend checks are **defensive** - all actual authorization decisions are made by the backend API, which calls the Stratium platform service for each request.

## Application Structure

\`\`\`
src/
├── api/
│   └── client.ts              # API client with auth interceptors
├── components/
│   ├── Layout.tsx             # Main layout with navigation
│   └── ProtectedRoute.tsx     # Route wrapper for auth checks
├── contexts/
│   └── AuthContext.tsx        # Keycloak auth state management
├── hooks/
│   └── usePermissions.ts      # ABAC permission logic
├── pages/
│   ├── DatasetDetail.tsx      # Dataset view with permissions UI
│   ├── DatasetForm.tsx        # Create/edit dataset
│   ├── DatasetsList.tsx       # Browse and search datasets
│   ├── Home.tsx               # Landing page
│   ├── Login.tsx              # Keycloak login flow
│   ├── Unauthorized.tsx       # 403 error page
│   └── UsersList.tsx          # Admin-only user management
├── types/
│   └── index.ts               # TypeScript type definitions
├── config/
│   └── keycloak.ts            # Keycloak configuration
├── App.tsx                    # Main app with routing
└── main.tsx                   # App entry point
\`\`\`

## Docker Deployment

### Build Docker Image

\`\`\`bash
npm run docker:build
# or
docker build -t stratium-research-ui .
\`\`\`

### Run with Docker Compose

\`\`\`bash
npm run docker:run
# or
docker-compose up -d
\`\`\`

The containerized app will be available on **port 3000**.

### Docker Configuration

- Uses **multi-stage build** (Node.js build → Nginx serve)
- Production-ready **Nginx** configuration
- Gzip compression enabled
- Static asset caching
- SPA routing support

## Key Features Explained

### 1. Keycloak Integration

The app uses **Authorization Code Flow with PKCE** for secure authentication:

\`\`\`typescript
// Silent SSO check on load
keycloak.init({
  onLoad: 'check-sso',
  silentCheckSsoRedirectUri: '/silent-check-sso.html',
  pkceMethod: 'S256',
});
\`\`\`

Token claims are extracted and used for permission checks:
- \`email\`, \`name\`, \`department\`, \`role\`

### 2. Protected Routes

Routes are protected by role requirements:

\`\`\`typescript
<Route
  path="/datasets/new"
  element={
    <ProtectedRoute requiredRole="editor">
      <DatasetForm />
    </ProtectedRoute>
  }
/>
\`\`\`

### 3. Conditional UI Rendering

UI elements appear/disappear based on ABAC permissions:

\`\`\`typescript
const DatasetDetail = () => {
  const permissions = usePermissions(dataset);

  return (
    <>
      {permissions.canEdit && <EditButton />}
      {permissions.canDelete && <DeleteButton />}
      <PermissionBadges permissions={permissions} />
    </>
  );
};
\`\`\`

### 4. API Error Handling

The API client handles 401/403 errors gracefully:
- **401**: Attempts token refresh, redirects to login if needed
- **403**: Shows ABAC denial reason to user

### 5. Department-Scoped Search

The datasets list automatically filters by department:

\`\`\`typescript
// Backend ABAC policies ensure users only see their department's data
const { data } = useQuery({
  queryKey: ['datasets'],
  queryFn: () => apiClient.getDatasets(),
});
\`\`\`

## Development Tips

### Hot Module Replacement (HMR)

Vite provides instant updates during development. Edit any component and see changes immediately without losing state.

### TypeScript

The project uses strict TypeScript. All API types are defined in \`src/types/index.ts\`.

### Debugging Auth Issues

If login fails:
1. Check Keycloak is running: http://localhost:8080
2. Verify the client exists: Admin Console → Clients → micro-research-ui
3. Check browser console for token errors
4. Ensure redirect URIs match your dev URL

### Testing Different Roles

Log out and log in as different users to test role-based UI changes:
- **Viewer**: Limited to read-only, no create/edit/delete buttons
- **Editor**: Can create/edit, delete own datasets
- **Admin**: Full access, can see users page

## Architecture Diagram

\`\`\`
┌─────────────────┐
│   React UI      │
│  (Port 3000)    │
└────────┬────────┘
         │
         ├─── Keycloak (OIDC) ──────────────────────┐
         │    http://localhost:8080/realms/stratium  │
         │                                            │
         ├─── Backend API ───────────────────────────┤
         │    http://localhost:8888/api/v1           │
         │                                            │
         │                                            ▼
         │                                   ┌────────────────┐
         │                                   │   Platform     │
         │                                   │   Service      │
         │                                   │  (ABAC/gRPC)   │
         │                                   │  Port 50051    │
         └───────────────────────────────────┴────────────────┘
\`\`\`

## API Integration

The UI consumes these API endpoints:

| Endpoint | Method | Description | Auth Required | ABAC Checked |
|----------|--------|-------------|---------------|--------------|
| \`/api/v1/users/me\` | GET | Get current user | ✓ | - |
| \`/api/v1/users\` | GET | List all users | ✓ (admin) | ✓ |
| \`/api/v1/datasets\` | GET | List datasets | ✓ | ✓ (filtered) |
| \`/api/v1/datasets/search\` | GET | Search datasets | ✓ | ✓ (filtered) |
| \`/api/v1/datasets/:id\` | GET | Get dataset | ✓ | ✓ |
| \`/api/v1/datasets\` | POST | Create dataset | ✓ | ✓ |
| \`/api/v1/datasets/:id\` | PUT | Update dataset | ✓ | ✓ |
| \`/api/v1/datasets/:id\` | DELETE | Delete dataset | ✓ | ✓ |

All dataset operations are subject to ABAC policies enforced by the platform service.

## Troubleshooting

### "Network Error" when accessing API

- Ensure the backend API is running on port 8888
- Check CORS settings in the API
- Verify \`VITE_API_BASE_URL\` in \`.env\`

### "Invalid Client" during login

- Run \`./create-keycloak-client.sh\` to create the client
- Verify client ID matches \`.env\` configuration
- Check redirect URIs include your dev URL

### "Forbidden" errors when viewing datasets

- This is expected! ABAC policies restrict access
- Try a different user from another department
- Check browser console for ABAC denial reasons

### Datasets not appearing

- You may be logged in as a user in a department with no datasets
- Try logging in as \`alice@example.com\` (engineering) - has many datasets
- Or create new datasets as an editor/admin

## License

MIT

## Related Documentation

- [Backend API README](../api/README.md)
- [ABAC Policy Examples](../api/docs/example-policies.md)
- [Stratium Platform Documentation](../../../README.md)