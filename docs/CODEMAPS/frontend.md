<!-- Generated: 2026-03-28 | PAP UI Frontend | Files scanned: 73 TSX/TS | Token estimate: ~650 -->

# Frontend Codemap

**Last Updated:** 2026-03-28

## Tech Stack

React 18, TypeScript, Vite, Shadcn/UI, TanStack Query, React Router, Tailwind CSS, Keycloak JS

## Route Tree

```
/login                → Login.tsx (public)
/                     → Index.tsx (dashboard, protected)
/policies             → Policies.tsx (list, protected)
/policies/:id         → PolicyForm.tsx (create/edit, protected)
/entitlements         → Entitlements.tsx (list, protected)
/entitlements/:id     → EntitlementForm.tsx (create/edit, protected)
/audit-logs           → AuditLogs.tsx (viewer, protected)
*                     → NotFound.tsx
```

**Entry**: `pap-ui/src/main.tsx` → `App.tsx` (providers + router)

## Component Hierarchy

```
App.tsx
├── QueryClientProvider (TanStack Query)
├── TooltipProvider (Shadcn)
├── AuthProvider (Keycloak OIDC)
├── Toaster + Sonner (notifications)
└── BrowserRouter
    ├── Login
    ├── ProtectedRoute → Layout → [Page]
    └── NotFound
```

## State Management

- **Auth**: `contexts/AuthContext.tsx` — Keycloak JS adapter, token auto-refresh
- **Server state**: TanStack Query via custom hooks:
  - `hooks/use-policies.ts` — policy CRUD queries/mutations
  - `hooks/use-entitlements.ts` — entitlement CRUD queries/mutations
  - `hooks/use-audit-logs.ts` — audit log queries

## API Client

**File**: `lib/api-client.ts`

```
ApiClient (class)
├── keycloak: Keycloak (auto token refresh via updateToken(30))
├── getAuthHeaders() → Bearer token header
├── request<T>(endpoint, options) → JSON response
├── getPolicies() / createPolicy() / updatePolicy() / deletePolicy()
├── getEntitlements() / createEntitlement() / updateEntitlement() / deleteEntitlement()
└── getAuditLogs()
```

**Base URL**: `VITE_PAP_API_URL` env var (default: `http://localhost:8090`)

## Auth Flow

```
User → /login → Keycloak JS adapter
  → keycloak.init({ onLoad: 'login-required' })
  → Token stored in Keycloak JS instance
  → ApiClient.getAuthHeaders() → Bearer token
  → ProtectedRoute checks keycloak.authenticated
```

**Config**: `config/keycloak.ts` — Keycloak realm, client ID, URL

## Key Files

```
pap-ui/src/
├── App.tsx                      (root: providers + routes)
├── main.tsx                     (Vite entry point)
├── contexts/AuthContext.tsx      (Keycloak auth state)
├── lib/api-client.ts            (PAP API HTTP client)
├── lib/utils.ts                 (cn() classname utility)
├── config/keycloak.ts           (OIDC config)
├── types/models.ts              (Policy, Entitlement, AuditLog types)
├── utils/storage.ts             (localStorage helpers)
├── components/
│   ├── Layout.tsx               (nav + page shell)
│   ├── ProtectedRoute.tsx       (auth guard)
│   └── ui/                      (50+ Shadcn components)
├── hooks/
│   ├── use-policies.ts          (TanStack Query hooks)
│   ├── use-entitlements.ts
│   ├── use-audit-logs.ts
│   └── use-mobile.tsx
└── pages/
    ├── Index.tsx                 (dashboard)
    ├── Policies.tsx              (policy list)
    ├── PolicyForm.tsx            (policy editor: OPA/XACML/JSON)
    ├── Entitlements.tsx          (entitlement list)
    ├── EntitlementForm.tsx       (entitlement editor)
    ├── AuditLogs.tsx             (audit viewer)
    ├── Login.tsx
    └── NotFound.tsx
```

## Build & Deploy

- **Dev**: `npm run dev` (Vite dev server, HMR)
- **Build**: `npm run build` → `dist/`
- **Docker**: `deployment/docker/Dockerfile.pap` (separate from backend)
- **Port**: 3000 (Docker), 5173 (Vite dev)

## Related Documentation

- **Backend API**: `/docs/CODEMAPS/backend.md` (PAP REST endpoints consumed by this UI)
- **Architecture**: `/docs/CODEMAPS/architecture.md`
- **Data Models**: `/docs/CODEMAPS/data.md` (Policy, Entitlement, AuditLog types)
