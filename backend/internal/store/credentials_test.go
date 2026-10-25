package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
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
	enroll := func(t *testing.T, s Store, tenant, serial string, key []byte, at time.Time) EnrollResult {
		t.Helper()
		res, err := s.Enroll(ctx, DeviceCredential{
			DeviceID: newUUID(t), TenantID: tenant, Serial: serial, HardwareUUID: "HW-" + serial,
			PublicKey: key, CreatedAt: at,
		})
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
		})
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
		})
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
		})
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
			})
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
			replaced.Previous.DeviceID != first.Credential.DeviceID || replaced.Previous.KeyStorage != KeyStorageSecureEnclave {
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
