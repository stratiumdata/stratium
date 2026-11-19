module github.com/stratiumdata/stratium/example

go 1.26.0

toolchain go1.26.11

require (
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.10.9
	github.com/stratiumdata/stratium v0.0.0
	google.golang.org/grpc v1.83.2
)

require (
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace stratium => ../services

replace github.com/stratiumdata/stratium => ../services
