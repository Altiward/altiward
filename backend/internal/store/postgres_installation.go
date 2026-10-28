package store

import "context"

func (p *Postgres) Installation(ctx context.Context) (Installation, error) {
	var in Installation
	err := p.pool.QueryRow(ctx, `SELECT created_at, raised_id_secret, admin_group_started_at, admin_group_backfilled_at
		FROM installation`).Scan(&in.CreatedAt, &in.RaisedIDSecret, &in.AdminGroupStartedAt, &in.AdminGroupBackfilledAt)
	return in, err
}
