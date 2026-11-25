package store

import "database/sql"

// LimitPool caps how many connections db opens at once. database/sql's own
// default is no limit, so a process under load opens one per request in
// flight until Postgres runs out for every client it serves. With a cap, a
// request past it waits for a connection until its own context ends.
//
// ponytail: idle connections stay at database/sql's default of two, so a busy
// process reconnects often; raise SetMaxIdleConns if connect time shows up in
// decision latency.
func LimitPool(db *sql.DB, maxOpen int) {
	db.SetMaxOpenConns(maxOpen)
}
