package store

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// installationSuite checks the record of this server: when it was set up.
func installationSuite(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()

	t.Run("a new installation has a start", func(t *testing.T) {
		in, err := newStore(t).Installation(ctx)
		if err != nil || in.CreatedAt.IsZero() {
			t.Fatalf("installation = %+v, %v", in, err)
		}
	})

	t.Run("the secret for raised event IDs is 32 bytes and stays the same", func(t *testing.T) {
		s := newStore(t)
		first, err := s.Installation(ctx)
		if err != nil || len(first.RaisedIDSecret) != 32 {
			t.Fatalf("installation = %+v, %v", first, err)
		}
		second, err := s.Installation(ctx)
		if err != nil || !bytes.Equal(first.RaisedIDSecret, second.RaisedIDSecret) {
			t.Fatalf("secret changed: %x then %x, %v", first.RaisedIDSecret, second.RaisedIDSecret, err)
		}
	})

	t.Run("the admin group has a start and no backfill yet", func(t *testing.T) {
		in, err := newStore(t).Installation(ctx)
		if err != nil || in.AdminGroupStartedAt.IsZero() || in.AdminGroupBackfilledAt != nil {
			t.Fatalf("installation = %+v, %v", in, err)
		}
	})
}

func TestMemoryInstallation(t *testing.T) {
	installationSuite(t, func(t *testing.T) Store { return NewMemory(nil) })
}

// TestPostgresInstallation gives each case its own schema: the installation row is one per
// database.
func TestPostgresInstallation(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	open := func(t *testing.T) Store {
		s, err := OpenPostgres(context.Background(), inSchema(t, url, "install_"+randomHex(t)), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	installationSuite(t, open)

	t.Run("stats name the installation once migrated", func(t *testing.T) {
		s := open(t).(*Postgres)
		st, err := s.Stats(context.Background(), testfixture.Time(t, "2026-10-19T12:00:00Z"))
		if err != nil || st.InstalledAt == nil {
			t.Fatalf("stats = %+v, %v", st, err)
		}
	})

	t.Run("stats before the database is migrated", func(t *testing.T) {
		ctx := context.Background()
		ro, err := ConnectPostgres(ctx, inSchema(t, url, "install_empty_"+randomHex(t)), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer ro.Close()
		names, err := fs.Glob(migrations, "migrations/*.sql")
		if err != nil {
			t.Fatal(err)
		}
		st, err := ro.Stats(ctx, testfixture.Time(t, "2026-10-19T12:00:00Z"))
		if err != nil || st.InstalledAt != nil || len(st.MigrationsPending) != len(names) || st.CountsSkipped == "" {
			t.Fatalf("stats = %+v, %v", st, err)
		}
	})
}
