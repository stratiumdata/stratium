Stratium Platform — Comprehensive Project Review
Executive Summary
The Stratium ZTDF platform is well-architected with clean service separation, consistent error handling, good documentation, and solid proto/API design. However, the review uncovered 5 CRITICAL security issues (one requiring immediate credential rotation), 12 HIGH issues across security, concurrency, and code quality, and 16 MEDIUM issues.

CRITICAL Issues (5) — Immediate Action Required
CRITICAL-1: Live AWS RDS credentials committed to git
deployment/helm/stratium/values-rds.yaml
Password StratiumDB2025 with full RDS hostname stratium-postgres.c388sq8a85dn.us-east-2.rds.amazonaws.com committed to version control.

Action: Rotate the RDS password immediately. Audit RDS access logs. Scrub from git history with git filter-repo.

CRITICAL-2: Auth interceptor falls back to unverified JWT parsing
go/pkg/auth/auth.go:226-244
When OIDC validation fails, the interceptor falls back to MockValidateToken which calls jwt.ParseUnverified — accepting any JWT without signature verification. An attacker can craft a JWT with "sub": "admin" during any OIDC provider blip.

Action: Remove MockValidateToken fallback from the production AuthInterceptor. Return codes.Unauthenticated on OIDC failure.

CRITICAL-3: HSM provider deadlock bug (unfixed)
go/services/key-manager/hsm_provider.go:102,207,293
GenerateKeyPair, DeleteKeyPair, and RotateKey acquire a write lock then call IsAvailable() which tries to acquire a read lock — guaranteed deadlock. RotateKey additionally calls GenerateKeyPair while holding the write lock (double deadlock). This was reported in a prior review and remains unfixed.

Action: Extract isAvailableLocked() (like SmartCardKeyProvider already does). Make RotateKey call a lock-free generateKeyPairLocked helper.

CRITICAL-4: gRPC reflection enabled unconditionally in production
go/cmd/key-manager-server/main.go:156, all three servers
reflection.Register(grpcServer) runs with no environment guard, allowing any client to enumerate all RPCs and message types.

Action: Gate behind cfg.IsDevelopment().

CRITICAL-5: pprof imported unconditionally in production binaries
go/cmd/key-manager-server/main.go:9, all three servers
_ "net/http/pprof" exposes heap dumps containing decrypted private keys and DEKs in the key manager's cache.

Action: Move to a //go:build debug guarded file.

HIGH Issues (12)
#	Category	File	Issue
1	Security	go/config/config.go:385	OIDC auth disabled by default — mock auth accepts any request
2	Security	go/config/config.go:364	Database sslmode defaults to disable — plaintext DB traffic
3	Security	go/services/key-manager/dek_service.go:252	YubiKey plain DEK envelope returns unencrypted DEK — client-controlled metadata can trigger it
4	Security	go/services/key-access/server.go:796	Textbook RSA (no padding) in production code path — comment says "simplified version"
5	Security	go/services/key-access/server.go:631	Non-canonical ECC coordinate serialization — big.Int.Bytes() strips leading zeros
6	Security	config YAML	CORS wildcard * with allow_credentials: true; rate limiting off by default
7	Concurrency	go/services/key-manager/hsm_provider.go:244	Sign/Decrypt/Encrypt check availability outside lock, then operate — TOCTOU race
8	Concurrency	go/services/key-access/server.go:754	Cache check-then-delete race — can evict a freshly-populated valid entry
9	Concurrency	go/services/key-manager/rotation_manager.go:238	Lock released mid-rotation — two goroutines can rotate the same key simultaneously
10	Code Quality	go/services/key-manager/hsm_provider.go:36	Mock types (MockHSMClient, MockCardReader) compiled into production binary
11	Code Quality	go/services/key-manager/server.go:78	Leaked DB connection — *sqlx.DB discarded, no Server.Close() method
12	Code Quality	go/services/key-manager/server.go:135	Rotation manager start failure logged at Info and silently ignored
Architecture Assessment
Area	Rating	Key Finding
Service Architecture	Good	Clean 4-service split (Platform, KAS, Key Manager, PAP). Duplicated createAuthServiceFromConfig should be unified.
File Sizes	Concerning	postgres_key_store.go (1012 lines), key-access/server.go (889 lines) exceed 800-line limit
Package Structure	Good	Clean pkg/ layout. But services/key-manager/ is a 97-file god package needing sub-packages
Error Handling	Good	Consistent %w wrapping. One errors.New(... + err.Error()) breaks the chain at key-access/server.go:200
Configuration	Good	Viper-based, well-structured. Hardcoded per-service rate limits should be configurable
Proto/API Design	Good	Clean conventions. Duplicated Condition message across protos should be shared
Deployment	Good	Multi-stage Docker, health checks. Runtime image uses golang:alpine (should be distroless/alpine)
SDK Consistency	Good	All 4 SDKs implement same wrap/unwrap flow. Go SDK diverges on key management (manual vs auto-register)
Documentation	Good	24 docs covering operations. Missing architecture/data-flow diagram
Dependencies	Needs Work	go 1.25 doesn't exist. Vendored Gin fork undocumented.
Go Code Quality Highlights
Issue	File	Impact
7 functions exceed 50 lines	NewServer (~130), WrapDEK (~120), UnwrapDEK (~107+95)	Hard to test and maintain
Logger data race	go/logging/logger.go:92	minLevel read without lock while SetLevel writes under lock
log.Printf bypasses structured logger	go/pkg/ztdf/keymanager.go (6 calls)	Unfiltered, unformatted output
isFIPSKeyTypeAllowed duplicated	key-manager + key-access	Maintenance hazard
KeyProviderInterface has 13 methods	go/services/key-manager/provider.go:9	Should be split into focused interfaces
Config argument mutated	go/services/key-manager/server.go:283	createAuthServiceFromConfig modifies caller's *config.Config
Top 10 Recommended Actions (Priority Order)
Rotate StratiumDB2025 RDS password NOW — scrub from git history
Remove MockValidateToken fallback from production auth interceptor
Fix HSM provider deadlocks — extract isAvailableLocked(), fix RotateKey double-lock
Gate reflection + pprof behind development mode / build tags
Change insecure defaults — oidc.enabled: true, sslmode: require, rate_limiting.enabled: true
Audit YubiKey plain DEK registrations — add server-side authorization for yubikey_touch_required metadata
Replace textbook RSA in key-access with proper rsa.VerifyPKCS1v15 or rsa.DecryptOAEP
Split oversized files — postgres_key_store.go, key-access/server.go; extract sub-packages from services/key-manager/
Move mock types (MockHSMClient, MockCardReader) out of production source files
Add HTTP timeouts to PAP server and implement graceful shutdown
Want me to start working on any of these fixes?