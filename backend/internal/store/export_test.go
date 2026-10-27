package store

import "context"

// lockTimeout reports the lock_timeout of whichever pooled connection answers; the tests
// that use it open the store with one connection.
func (p *Postgres) lockTimeout(ctx context.Context) (string, error) {
	var v string
	err := p.pool.QueryRow(ctx, `SHOW lock_timeout`).Scan(&v)
	return v, err
}
