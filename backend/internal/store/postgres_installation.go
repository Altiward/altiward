package store

import "context"

func (p *Postgres) Installation(ctx context.Context) (Installation, error) {
	var in Installation
	err := p.pool.QueryRow(ctx, `SELECT created_at FROM installation`).Scan(&in.CreatedAt)
	return in, err
}
