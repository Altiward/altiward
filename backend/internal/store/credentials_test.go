package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// credentialSuite runs the enrollment rules against a Store implementation.
func credentialSuite(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")

	setup := func(t *testing.T) (Store, string, string) {
		return newStore(t), "tenant-" + randomHex(t), "C02" + randomHex(t)
	}
	// enrollLimited enrols a key for a Mac whose hardware UUID is hardware, under limits.
	enrollLimited := func(s Store, tenant, serial, hardware string, key []byte, at time.Time, limits EnrollLimits) (EnrollResult, error) {
		id, err := NewDeviceID()
		if err != nil {
			return EnrollResult{}, err
		}
		return s.Enroll(ctx, DeviceCredential{
			DeviceID: id, TenantID: tenant, Serial: serial, HardwareUUID: hardware, PublicKey: key, CreatedAt: at,
		}, limits)
	}
	enroll := func(t *testing.T, s Store, tenant, serial string, key []byte, at time.Time) EnrollResult {
		t.Helper()
		res, err := enrollLimited(s, tenant, serial, "HW-"+serial, key, at, EnrollLimits{})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	lookup := func(t *testing.T, s Store, id string) DeviceCredential {
		t.Helper()
		c, err := s.Credential(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	t.Run("first enrollment is active", func(t *testing.T) {
		s, tenant, serial := setup(t)
		res := enroll(t, s, tenant, serial, newKey(t), t0)
		c := lookup(t, s, res.Credential.DeviceID)
		if c.Status != CredentialActive || res.Replaced != "" || c.Serial != serial || c.TenantID != tenant {
			t.Fatalf("credential = %+v replaced = %q", c, res.Replaced)
		}
		if c.ActivatedAt == nil || !c.ActivatedAt.Equal(t0) || c.RevokedAt != nil {
			t.Fatalf("times = %v %v", c.ActivatedAt, c.RevokedAt)
		}
	})

	t.Run("retry with the same key returns the same credential", func(t *testing.T) {
		s, tenant, serial := setup(t)
		key := newKey(t)
		first := enroll(t, s, tenant, serial, key, t0)
		again := enroll(t, s, tenant, serial, key, t0.Add(time.Minute))
		if again.Credential.DeviceID != first.Credential.DeviceID || again.Replaced != "" {
			t.Fatalf("retry = %+v, first = %+v", again, first)
		}
	})

	t.Run("where the key is kept is recorded once", func(t *testing.T) {
		s, tenant, serial := setup(t)
		key := newKey(t)
		res, err := s.Enroll(ctx, DeviceCredential{
			DeviceID: newUUID(t), TenantID: tenant, Serial: serial, HardwareUUID: "HW", PublicKey: key,
			KeyStorage: KeyStorageSecureEnclave, CreatedAt: t0,
		}, EnrollLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if c := lookup(t, s, res.Credential.DeviceID); c.KeyStorage != KeyStorageSecureEnclave {
			t.Fatalf("key storage = %q", c.KeyStorage)
		}
		// A retry claiming otherwise doesn't change it.
		again, err := s.Enroll(ctx, DeviceCredential{
			DeviceID: newUUID(t), TenantID: tenant, Serial: serial, HardwareUUID: "HW", PublicKey: key,
			KeyStorage: KeyStorageSoftware, CreatedAt: t0.Add(time.Minute),
		}, EnrollLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if again.Credential.KeyStorage != KeyStorageSecureEnclave || lookup(t, s, res.Credential.DeviceID).KeyStorage != KeyStorageSecureEnclave {
			t.Fatalf("after retry: %q", again.Credential.KeyStorage)
		}
		list, err := s.ListCredentials(ctx, tenant, CredentialFilter{})
		if err != nil || len(list) != 1 || list[0].KeyStorage != KeyStorageSecureEnclave {
			t.Fatalf("list = %+v, %v", list, err)
		}
	})

	t.Run("a key enrolled in another tenant is refused", func(t *testing.T) {
		s, tenant, serial := setup(t)
		key := newKey(t)
		enroll(t, s, tenant, serial, key, t0)
		_, err := s.Enroll(ctx, DeviceCredential{
			DeviceID: newUUID(t), TenantID: tenant + "-other", Serial: serial, HardwareUUID: "HW", PublicKey: key, CreatedAt: t0,
		}, EnrollLimits{})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("re-enrollment replaces only after an explicit opt-out", func(t *testing.T) {
		s, tenant, serial := setup(t)
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{ReenrollmentRequiresApproval: false}, auditFor(t, tenant, AuditChangeSettings)); err != nil {
			t.Fatal(err)
		}
		old := enroll(t, s, tenant, serial, newKey(t), t0)
		res := enroll(t, s, tenant, serial, newKey(t), t0.Add(time.Hour))
		if res.Credential.Status != CredentialActive || res.Replaced != old.Credential.DeviceID {
			t.Fatalf("new = %+v replaced = %q", res.Credential, res.Replaced)
		}
		prev := lookup(t, s, old.Credential.DeviceID)
		if prev.Status != CredentialRevoked || prev.RevokedAt == nil || !prev.RevokedAt.Equal(t0.Add(time.Hour)) {
			t.Fatalf("old = %+v", prev)
		}
	})

	t.Run("re-enrollment waits for approval by default", func(t *testing.T) {
		s, tenant, serial := setup(t)
		old := enroll(t, s, tenant, serial, newKey(t), t0)
		if old.Credential.Status != CredentialActive {
			t.Fatalf("first enrollment = %s, want active even with approval on", old.Credential.Status)
		}
		key := newKey(t)
		res := enroll(t, s, tenant, serial, key, t0.Add(time.Hour))
		again := enroll(t, s, tenant, serial, key, t0.Add(90*time.Minute))
		if again.Credential.DeviceID != res.Credential.DeviceID || again.Credential.Status != CredentialPending || again.Replaced != "" {
			t.Fatalf("pending retry = %+v", again)
		}
		if res.Credential.Status != CredentialPending || res.Replaced != "" {
			t.Fatalf("re-enrollment = %+v", res)
		}
		if lookup(t, s, old.Credential.DeviceID).Status != CredentialActive {
			t.Fatal("old credential stopped working before approval")
		}

		approved, err := s.ApproveCredential(ctx, tenant, res.Credential.DeviceID, t0.Add(2*time.Hour), auditFor(t, tenant, AuditApproveEnrollment))
		if err != nil {
			t.Fatal(err)
		}
		if approved.Status != CredentialActive || !approved.ActivatedAt.Equal(t0.Add(2*time.Hour)) {
			t.Fatalf("approved = %+v", approved)
		}
		if lookup(t, s, old.Credential.DeviceID).Status != CredentialRevoked {
			t.Fatal("old credential still active after approval")
		}
		if _, err := s.ApproveCredential(ctx, tenant, res.Credential.DeviceID, t0, auditFor(t, tenant, AuditApproveEnrollment)); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("second approval err = %v", err)
		}
	})

	t.Run("enrollment reports the previous active credential", func(t *testing.T) {
		s, tenant, serial := setup(t)
		enrollStored := func(key []byte, hardware string, storage KeyStorage, at time.Time) EnrollResult {
			t.Helper()
			res, err := s.Enroll(ctx, DeviceCredential{
				DeviceID: newUUID(t), TenantID: tenant, Serial: serial, HardwareUUID: hardware, PublicKey: key,
				KeyStorage: storage, CreatedAt: at,
			}, EnrollLimits{})
			if err != nil {
				t.Fatal(err)
			}
			return res
		}
		first := enrollStored(newKey(t), "HW-FIRST", KeyStorageSecureEnclave, t0)
		if first.Previous != nil {
			t.Fatalf("a first key has no previous credential: %+v", first.Previous)
		}

		// With approval on, the new key waits and the active one is still in use.
		pendingKey := newKey(t)
		pending := enrollStored(pendingKey, "HW-OTHER", KeyStorageSoftware, t0.Add(time.Hour))
		if pending.Credential.Status != CredentialPending || pending.Previous == nil {
			t.Fatalf("pending = %+v previous = %+v", pending.Credential, pending.Previous)
		}
		if p := pending.Previous; p.DeviceID != first.Credential.DeviceID || p.HardwareUUID != "HW-FIRST" ||
			p.KeyStorage != KeyStorageSecureEnclave || p.Status != CredentialActive {
			t.Fatalf("previous = %+v, want the first credential as it was", p)
		}
		// A retry of the pending key is not a new enrolment, so it reports nothing.
		if again := enrollStored(pendingKey, "HW-OTHER", KeyStorageSoftware, t0.Add(90*time.Minute)); again.Previous != nil {
			t.Fatalf("a retry reported a previous credential: %+v", again.Previous)
		}

		// With approval off, the new key replaces the active one, and Previous names it.
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{ReenrollmentRequiresApproval: false}, auditFor(t, tenant, AuditChangeSettings)); err != nil {
			t.Fatal(err)
		}
		replaced := enrollStored(newKey(t), "HW-FIRST", KeyStorageSoftware, t0.Add(2*time.Hour))
		if replaced.Replaced != first.Credential.DeviceID || replaced.Previous == nil ||
			replaced.Previous.DeviceID != first.Credential.DeviceID || replaced.Previous.KeyStorage != KeyStorageSecureEnclave ||
			replaced.Previous.Status != CredentialActive {
			t.Fatalf("replaced = %+v previous = %+v", replaced, replaced.Previous)
		}

		// Once nothing is active, a new key has no previous credential to report.
		if _, err := s.RevokeCredential(ctx, tenant, replaced.Credential.DeviceID, t0.Add(3*time.Hour), auditFor(t, tenant, AuditRevokeEnrollment)); err != nil {
			t.Fatal(err)
		}
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{ReenrollmentRequiresApproval: true}, auditFor(t, tenant, AuditChangeSettings)); err != nil {
			t.Fatal(err)
		}
		afterRevoke := enrollStored(newKey(t), "HW-FIRST", KeyStorageSoftware, t0.Add(4*time.Hour))
		if afterRevoke.Credential.Status != CredentialPending || afterRevoke.Previous != nil {
			t.Fatalf("after revoke = %+v previous = %+v", afterRevoke.Credential, afterRevoke.Previous)
		}
	})

	t.Run("a revoked Mac cannot re-enroll by default", func(t *testing.T) {
		s, tenant, serial := setup(t)
		oldKey := newKey(t)
		old := enroll(t, s, tenant, serial, oldKey, t0)
		if _, err := s.RevokeCredential(ctx, tenant, old.Credential.DeviceID, t0.Add(time.Minute), auditFor(t, tenant, AuditRevokeEnrollment)); err != nil {
			t.Fatal(err)
		}
		if again := enroll(t, s, tenant, serial, oldKey, t0.Add(30*time.Minute)); again.Credential.Status != CredentialRevoked || again.Credential.DeviceID != old.Credential.DeviceID {
			t.Fatalf("revoked key retry = %+v", again)
		}
		res := enroll(t, s, tenant, serial, newKey(t), t0.Add(time.Hour))
		if res.Credential.Status != CredentialPending {
			t.Fatalf("re-enrollment after revoke = %s, want pending", res.Credential.Status)
		}
	})

	t.Run("revoke is idempotent and tenant-scoped", func(t *testing.T) {
		s, tenant, serial := setup(t)
		res := enroll(t, s, tenant, serial, newKey(t), t0)
		id := res.Credential.DeviceID
		if _, err := s.RevokeCredential(ctx, tenant+"-other", id, t0, auditFor(t, tenant, AuditRevokeEnrollment)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("other tenant revoke err = %v", err)
		}
		if _, err := s.ApproveCredential(ctx, tenant+"-other", id, t0, auditFor(t, tenant, AuditApproveEnrollment)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("other tenant approve err = %v", err)
		}
		first, err := s.RevokeCredential(ctx, tenant, id, t0.Add(time.Minute), auditFor(t, tenant, AuditRevokeEnrollment))
		if err != nil || first.Status != CredentialRevoked {
			t.Fatalf("revoke = %+v, %v", first, err)
		}
		again, err := s.RevokeCredential(ctx, tenant, id, t0.Add(time.Hour), auditFor(t, tenant, AuditRevokeEnrollment))
		if err != nil || !again.RevokedAt.Equal(t0.Add(time.Minute)) {
			t.Fatalf("second revoke = %+v, %v", again, err)
		}
	})

	t.Run("list filters by status and serial, newest first", func(t *testing.T) {
		s, tenant, serial := setup(t)
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{ReenrollmentRequiresApproval: false}, auditFor(t, tenant, AuditChangeSettings)); err != nil {
			t.Fatal(err)
		}
		a := enroll(t, s, tenant, serial, newKey(t), t0)
		b := enroll(t, s, tenant, serial, newKey(t), t0.Add(time.Hour)) // revokes a
		other := enroll(t, s, tenant, serial+"X", newKey(t), t0.Add(2*time.Hour))

		ids := func(f CredentialFilter) []string {
			cs, err := s.ListCredentials(ctx, tenant, f)
			if err != nil {
				t.Fatal(err)
			}
			out := []string{}
			for _, c := range cs {
				out = append(out, c.DeviceID)
			}
			return out
		}
		want := func(got []string, want ...string) {
			t.Helper()
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("got %v, want %v", got, want)
			}
		}
		want(ids(CredentialFilter{}), other.Credential.DeviceID, b.Credential.DeviceID, a.Credential.DeviceID)
		want(ids(CredentialFilter{Serial: serial}), b.Credential.DeviceID, a.Credential.DeviceID)
		want(ids(CredentialFilter{Status: CredentialRevoked}), a.Credential.DeviceID)
		cs, _ := s.ListCredentials(ctx, tenant+"-other", CredentialFilter{})
		if len(cs) != 0 {
			t.Errorf("other tenant sees %d credentials", len(cs))
		}
	})

	t.Run("unknown credential", func(t *testing.T) {
		s, _, _ := setup(t)
		if _, err := s.Credential(ctx, newUUID(t)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("tenant settings default and round-trip", func(t *testing.T) {
		s, tenant, _ := setup(t)
		got, err := s.TenantSettings(ctx, tenant)
		if err != nil || !got.ReenrollmentRequiresApproval {
			t.Fatalf("default = %+v, %v", got, err)
		}
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{ReenrollmentRequiresApproval: false}, auditFor(t, tenant, AuditChangeSettings)); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.TenantSettings(ctx, tenant); got.ReenrollmentRequiresApproval {
			t.Fatal("explicit opt-out not stored")
		}
	})

	// There is no Mac limit: the number of active Macs never decides a status.
	t.Run("enrollment has no Mac limit", func(t *testing.T) {
		s, tenant, _ := setup(t)
		for i := 0; i < 30; i++ {
			res := enroll(t, s, tenant, fmt.Sprintf("C02LIM%02d%s", i, randomHex(t)), newKey(t), t0)
			if res.Credential.Status != CredentialActive || res.Credential.ActivatedAt == nil {
				t.Fatalf("Mac %d = %+v", i+1, res.Credential)
			}
		}
		active, err := s.ListCredentials(ctx, tenant, CredentialFilter{Status: CredentialActive})
		if err != nil || len(active) != 30 {
			t.Fatalf("active = %d, %v", len(active), err)
		}
	})

	t.Run("a pending re-enrollment can be approved", func(t *testing.T) {
		s, tenant, serial := setup(t)
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{ReenrollmentRequiresApproval: true}, auditFor(t, tenant, AuditChangeSettings)); err != nil {
			t.Fatal(err)
		}
		enroll(t, s, tenant, serial, newKey(t), t0)
		again := enroll(t, s, tenant, serial, newKey(t), t0.Add(time.Hour))
		if again.Credential.Status != CredentialPending {
			t.Fatalf("re-enrollment = %s", again.Credential.Status)
		}
		approved, err := s.ApproveCredential(ctx, tenant, again.Credential.DeviceID, t0.Add(2*time.Hour), auditFor(t, tenant, AuditApproveEnrollment))
		if err != nil || approved.Status != CredentialActive {
			t.Fatalf("approve: %+v, %v", approved, err)
		}
	})

	// A tenant's enrolment token can add Macs without end, so a tenant may add only so many
	// new serials an hour. A serial is new when the tenant has no credential of any status
	// for it, and counts for the hour after its first key.
	t.Run("new Macs per hour are limited for each tenant", func(t *testing.T) {
		s, tenant, _ := setup(t)
		limits := EnrollLimits{NewMacsPerHour: 2}
		serial := func(n int) string { return fmt.Sprintf("C02NEW%d%s", n, randomHex(t)) }
		first, second, third, fourth := serial(1), serial(2), serial(3), serial(4)

		for i, sn := range []string{first, second} {
			if _, err := enrollLimited(s, tenant, sn, "HW-"+sn, newKey(t), t0.Add(time.Duration(i)*10*time.Minute), limits); err != nil {
				t.Fatalf("Mac %d: %v", i+1, err)
			}
		}
		if _, err := enrollLimited(s, tenant, third, "HW-"+third, newKey(t), t0.Add(20*time.Minute), limits); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("a third new Mac in the hour: err = %v, want ErrRateLimited", err)
		}
		if creds, err := s.ListCredentials(ctx, tenant, CredentialFilter{Serial: third}); err != nil || len(creds) != 0 {
			t.Fatalf("a refused enrolment left %d credentials, %v", len(creds), err)
		}
		// Another tenant has its own count.
		other := tenant + "-other"
		if _, err := enrollLimited(s, other, third, "HW-"+third, newKey(t), t0.Add(20*time.Minute), limits); err != nil {
			t.Fatalf("another tenant: %v", err)
		}
		// A Mac that already enrolled is not a new one, whatever the count: its next key is
		// held for approval, not refused.
		if res, err := enrollLimited(s, tenant, first, "HW-"+first, newKey(t), t0.Add(25*time.Minute), limits); err != nil || res.Credential.Status != CredentialPending {
			t.Fatalf("a known Mac's new key = %+v, %v", res.Credential, err)
		}
		// The hour rolls: the first Mac is an hour old, so only the second still counts.
		if _, err := enrollLimited(s, tenant, third, "HW-"+third, newKey(t), t0.Add(time.Hour), limits); err != nil {
			t.Fatalf("an hour after the first Mac: %v", err)
		}
		if _, err := enrollLimited(s, tenant, fourth, "HW-"+fourth, newKey(t), t0.Add(time.Hour), limits); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("a fourth new Mac: err = %v, want ErrRateLimited", err)
		}
	})

	// A Mac counts as new by its first key, so its later keys don't use up the allowance.
	t.Run("only a serial's first key counts as a new Mac", func(t *testing.T) {
		s, tenant, serial := setup(t)
		limits := EnrollLimits{NewMacsPerHour: 2}
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(-3*time.Hour), limits); err != nil {
			t.Fatal(err)
		}
		if res, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0, limits); err != nil || res.Credential.Status != CredentialPending {
			t.Fatalf("an old Mac's new key = %+v, %v", res.Credential, err)
		}
		for i := 0; i < 2; i++ {
			sn := fmt.Sprintf("C02ONLY%d%s", i, randomHex(t))
			if _, err := enrollLimited(s, tenant, sn, "HW-"+sn, newKey(t), t0, limits); err != nil {
				t.Fatalf("new Mac %d: %v", i+1, err)
			}
		}
		sn := "C02ONLY3" + randomHex(t)
		if _, err := enrollLimited(s, tenant, sn, "HW-"+sn, newKey(t), t0, limits); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("a third new Mac: err = %v, want ErrRateLimited", err)
		}
	})

	// A shared token could also pile keys onto one serial, so a serial may take only so many
	// in 24 hours, in any status.
	t.Run("keys per Mac per day are limited", func(t *testing.T) {
		s, tenant, serial := setup(t)
		limits := EnrollLimits{KeysPerMacPerDay: 2}
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0, limits); err != nil {
			t.Fatal(err)
		}
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(time.Hour), limits); err != nil {
			t.Fatal(err)
		}
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(2*time.Hour), limits); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("a third key in the day: err = %v, want ErrRateLimited", err)
		}
		if creds, err := s.ListCredentials(ctx, tenant, CredentialFilter{Serial: serial}); err != nil || len(creds) != 2 {
			t.Fatalf("%d credentials after a refusal, %v", len(creds), err)
		}
		// Another Mac of the same tenant has its own count.
		other := "C02OTHER" + randomHex(t)
		if _, err := enrollLimited(s, tenant, other, "HW", newKey(t), t0.Add(2*time.Hour), limits); err != nil {
			t.Fatalf("another Mac: %v", err)
		}
		// Revoking a key doesn't give its slot back.
		first, err := s.ListCredentials(ctx, tenant, CredentialFilter{Serial: serial, Status: CredentialActive})
		if err != nil || len(first) != 1 {
			t.Fatalf("active = %d, %v", len(first), err)
		}
		if _, err := s.RevokeCredential(ctx, tenant, first[0].DeviceID, t0.Add(3*time.Hour), auditFor(t, tenant, AuditRevokeEnrollment)); err != nil {
			t.Fatal(err)
		}
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(4*time.Hour), limits); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("after a revoke: err = %v, want ErrRateLimited", err)
		}
		// The day rolls: the first key is 24 hours old, so only the second still counts.
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(24*time.Hour), limits); err != nil {
			t.Fatalf("24 hours after the first key: %v", err)
		}
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(24*time.Hour+time.Minute), limits); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("a third key in the new day: err = %v, want ErrRateLimited", err)
		}
	})

	// The Mac that retries is the one already enrolled, so a limit never turns it away.
	t.Run("a retry is never limited", func(t *testing.T) {
		s, tenant, serial := setup(t)
		limits := EnrollLimits{NewMacsPerHour: 1, KeysPerMacPerDay: 2}
		activeKey, pendingKey := newKey(t), newKey(t)
		active, err := enrollLimited(s, tenant, serial, "HW", activeKey, t0, limits)
		if err != nil {
			t.Fatal(err)
		}
		pending, err := enrollLimited(s, tenant, serial, "HW", pendingKey, t0.Add(time.Minute), limits)
		if err != nil || pending.Credential.Status != CredentialPending {
			t.Fatalf("pending = %+v, %v", pending.Credential, err)
		}
		// The tenant is at its new-Mac limit and the serial at its key limit.
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(2*time.Minute), limits); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("a third key: err = %v, want ErrRateLimited", err)
		}
		for name, c := range map[string]struct {
			key  []byte
			want DeviceCredential
		}{"active": {activeKey, active.Credential}, "pending": {pendingKey, pending.Credential}} {
			again, err := enrollLimited(s, tenant, serial, "HW", c.key, t0.Add(3*time.Minute), limits)
			if err != nil || again.Credential.DeviceID != c.want.DeviceID || again.Credential.Status != c.want.Status {
				t.Fatalf("%s retry = %+v, %v", name, again.Credential, err)
			}
		}
		// Another tenant's key is a conflict, which is decided before any limit.
		if _, err := enrollLimited(s, tenant+"-other", "C02ELSE"+randomHex(t), "HW", activeKey, t0.Add(3*time.Minute), EnrollLimits{NewMacsPerHour: 1, KeysPerMacPerDay: 1}); !errors.Is(err, ErrConflict) {
			t.Fatalf("another tenant's key: err = %v, want ErrConflict", err)
		}
	})

	t.Run("zero means no limit", func(t *testing.T) {
		s, tenant, serial := setup(t)
		limits := EnrollLimits{}
		for i := 0; i < 40; i++ {
			sn := fmt.Sprintf("C02ZERO%02d%s", i, randomHex(t))
			if _, err := enrollLimited(s, tenant, sn, "HW-"+sn, newKey(t), t0, limits); err != nil {
				t.Fatalf("Mac %d: %v", i+1, err)
			}
		}
		for i := 0; i < 12; i++ {
			if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0, limits); err != nil {
				t.Fatalf("key %d: %v", i+1, err)
			}
		}
		// Each limit stands alone: one at 0 leaves the other in force.
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0, EnrollLimits{NewMacsPerHour: 1}); err != nil {
			t.Fatalf("only the new-Mac limit set: %v", err)
		}
		sn := "C02ZERO-X" + randomHex(t)
		if _, err := enrollLimited(s, tenant, sn, "HW", newKey(t), t0, EnrollLimits{KeysPerMacPerDay: 1}); err != nil {
			t.Fatalf("only the key limit set, a first key: %v", err)
		}
	})

	// The limits are counted under the database's locks, so requests made at once can't
	// all see room for one more.
	t.Run("limits hold when Macs enrol at the same moment", func(t *testing.T) {
		s, tenant, serial := setup(t)
		const attempts = 12
		race := func(limits EnrollLimits, serialFor func(i int) string) (ok, limited int) {
			var wg sync.WaitGroup
			var mu sync.Mutex
			for i := 0; i < attempts; i++ {
				key, sn := newKey(t), serialFor(i)
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := enrollLimited(s, tenant, sn, "HW", key, t0, limits)
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						ok++
					case errors.Is(err, ErrRateLimited):
						limited++
					default:
						t.Errorf("enrol: %v", err)
					}
				}()
			}
			wg.Wait()
			return ok, limited
		}
		ok, limited := race(EnrollLimits{NewMacsPerHour: 3}, func(i int) string { return fmt.Sprintf("C02RACE%02d%s", i, randomHex(t)) })
		if ok != 3 || limited != attempts-3 {
			t.Fatalf("new Macs: %d enrolled and %d refused, want 3 and %d", ok, limited, attempts-3)
		}
		ok, limited = race(EnrollLimits{KeysPerMacPerDay: 4}, func(int) string { return serial })
		if ok != 4 || limited != attempts-4 {
			t.Fatalf("keys for one Mac: %d enrolled and %d refused, want 4 and %d", ok, limited, attempts-4)
		}
	})

	// A key from different hardware is a different Mac claiming the serial, which an admin
	// should see even when the tenant has turned approval off for reinstalls.
	t.Run("a key from different hardware waits even with approval off", func(t *testing.T) {
		s, tenant, serial := setup(t)
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{ReenrollmentRequiresApproval: false}, auditFor(t, tenant, AuditChangeSettings)); err != nil {
			t.Fatal(err)
		}
		first, err := enrollLimited(s, tenant, serial, "HW-ORIGINAL", newKey(t), t0, EnrollLimits{})
		if err != nil || first.Credential.Status != CredentialActive {
			t.Fatalf("first = %+v, %v", first.Credential, err)
		}
		other, err := enrollLimited(s, tenant, serial, "HW-SOMEONE-ELSE", newKey(t), t0.Add(time.Hour), EnrollLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if other.Credential.Status != CredentialPending || other.Credential.ActivatedAt != nil || other.Replaced != "" {
			t.Fatalf("other hardware = %+v replaced = %q, want pending and nothing replaced", other.Credential, other.Replaced)
		}
		if other.Previous == nil || other.Previous.DeviceID != first.Credential.DeviceID {
			t.Fatalf("previous = %+v, want the first credential", other.Previous)
		}
		if lookup(t, s, first.Credential.DeviceID).Status != CredentialActive {
			t.Fatal("the active credential was replaced before approval")
		}
		// The same hardware still replaces, as the tenant chose.
		same, err := enrollLimited(s, tenant, serial, "HW-ORIGINAL", newKey(t), t0.Add(2*time.Hour), EnrollLimits{})
		if err != nil || same.Credential.Status != CredentialActive || same.Replaced != first.Credential.DeviceID {
			t.Fatalf("same hardware = %+v replaced = %q, %v", same.Credential, same.Replaced, err)
		}
		if lookup(t, s, first.Credential.DeviceID).Status != CredentialRevoked {
			t.Fatal("the first credential is still active")
		}
		// Approving the held key is the admin's call, and then it is the Mac.
		approved, err := s.ApproveCredential(ctx, tenant, other.Credential.DeviceID, t0.Add(3*time.Hour), auditFor(t, tenant, AuditApproveEnrollment))
		if err != nil || approved.Status != CredentialActive {
			t.Fatalf("approved = %+v, %v", approved, err)
		}
		if lookup(t, s, same.Credential.DeviceID).Status != CredentialRevoked {
			t.Fatal("the replaced key is still active after the approval")
		}
	})

	// With nothing active there is no hardware to compare to, so approval alone decides.
	t.Run("different hardware needs an active key to be compared with", func(t *testing.T) {
		s, tenant, serial := setup(t)
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{ReenrollmentRequiresApproval: false}, auditFor(t, tenant, AuditChangeSettings)); err != nil {
			t.Fatal(err)
		}
		first, err := enrollLimited(s, tenant, serial, "HW-ORIGINAL", newKey(t), t0, EnrollLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RevokeCredential(ctx, tenant, first.Credential.DeviceID, t0.Add(time.Minute), auditFor(t, tenant, AuditRevokeEnrollment)); err != nil {
			t.Fatal(err)
		}
		res, err := enrollLimited(s, tenant, serial, "HW-SOMEONE-ELSE", newKey(t), t0.Add(time.Hour), EnrollLimits{})
		if err != nil || res.Credential.Status != CredentialActive || res.Previous != nil {
			t.Fatalf("after a revoke = %+v previous = %+v, %v", res.Credential, res.Previous, err)
		}
	})
}

func newKey(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newUUID(t *testing.T) string {
	t.Helper()
	id, err := NewDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
