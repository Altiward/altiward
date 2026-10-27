package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/event"
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

	// A leaked token can be retired and the keys it made found: each credential keeps the
	// token that enrolled it, and a retry of the same key doesn't change it.
	t.Run("a credential keeps the token that enrolled it", func(t *testing.T) {
		s, tenant, serial := setup(t)
		key := newKey(t)
		enrollWith := func(token string, at time.Time) DeviceCredential {
			t.Helper()
			id, err := NewDeviceID()
			if err != nil {
				t.Fatal(err)
			}
			res, err := s.Enroll(ctx, DeviceCredential{
				DeviceID: id, TenantID: tenant, Serial: serial, HardwareUUID: "HW", PublicKey: key, Token: token, CreatedAt: at,
			}, EnrollLimits{})
			if err != nil {
				t.Fatal(err)
			}
			return res.Credential
		}
		first := enrollWith("token:1a2b3c4d", t0)
		if first.Token != "token:1a2b3c4d" || lookup(t, s, first.DeviceID).Token != "token:1a2b3c4d" {
			t.Fatalf("enrolled %+v, stored %+v", first, lookup(t, s, first.DeviceID))
		}
		if retry := enrollWith("token:99999999", t0.Add(time.Minute)); retry.DeviceID != first.DeviceID || retry.Token != "token:1a2b3c4d" {
			t.Fatalf("a retry with another token = %+v", retry)
		}
		if creds, err := s.ListCredentials(ctx, tenant, CredentialFilter{Serial: serial}); err != nil || len(creds) != 1 || creds[0].Token != "token:1a2b3c4d" {
			t.Fatalf("listed %+v, %v", creds, err)
		}
	})

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

	// A tenant that approves every new Mac holds a serial's first key too; it's off unless
	// turned on, and doesn't change how a known serial's next key is treated.
	t.Run("approving every new Mac holds a first key", func(t *testing.T) {
		s, tenant, serial := setup(t)
		if got, err := s.TenantSettings(ctx, tenant); err != nil || got.NewMacRequiresApproval {
			t.Fatalf("default = %+v, %v; want new Macs not held", got, err)
		}
		if err := s.PutTenantSettings(ctx, tenant, TenantSettings{NewMacRequiresApproval: true}, auditFor(t, tenant, AuditChangeSettings)); err != nil {
			t.Fatal(err)
		}
		first := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		if first.Status != CredentialPending || first.ActivatedAt != nil {
			t.Fatalf("a new Mac's first key = %+v, want pending", first)
		}
		if c, err := s.ApproveCredential(ctx, tenant, first.DeviceID, t0.Add(time.Minute), auditFor(t, tenant, AuditApproveEnrollment)); err != nil || c.Status != CredentialActive {
			t.Fatalf("approve = %+v, %v", c, err)
		}
		// With re-enrolment approval off, the known serial's next key replaces the first.
		if res := enroll(t, s, tenant, serial, newKey(t), t0.Add(time.Hour)); res.Credential.Status != CredentialActive || res.Replaced != first.DeviceID {
			t.Fatalf("a known Mac's next key = %+v, replaced %q", res.Credential, res.Replaced)
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

	t.Run("re-approving an approved key is refused", func(t *testing.T) {
		s, tenant, serial := setup(t)
		enroll(t, s, tenant, serial, newKey(t), t0)
		pending, err := enrollLimited(s, tenant, serial, "HW-other", newKey(t), t0.Add(time.Hour), EnrollLimits{})
		if err != nil || pending.Credential.Status != CredentialPending {
			t.Fatalf("different hardware = %+v, %v", pending.Credential, err)
		}
		id := pending.Credential.DeviceID
		if _, err := s.ApproveCredential(ctx, tenant, id, t0.Add(2*time.Hour), auditFor(t, tenant, AuditApproveEnrollment)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ApproveCredential(ctx, tenant, id, t0.Add(3*time.Hour), auditFor(t, tenant, AuditApproveEnrollment)); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("second approval = %v, want %v", err, ErrInvalidState)
		}
		if c := lookup(t, s, id); c.Status != CredentialActive {
			t.Fatalf("after the refused approval = %s", c.Status)
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

	// A new Mac with several keys in its first hour is still one new Mac.
	t.Run("a new Mac counts once whatever its keys", func(t *testing.T) {
		s, tenant, serial := setup(t)
		limits := EnrollLimits{NewMacsPerHour: 2}
		for i := 0; i < 3; i++ {
			if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(time.Duration(i)*time.Minute), limits); err != nil {
				t.Fatalf("key %d: %v", i+1, err)
			}
		}
		sn := "C02ONCE" + randomHex(t)
		if _, err := enrollLimited(s, tenant, sn, "HW-"+sn, newKey(t), t0.Add(5*time.Minute), limits); err != nil {
			t.Fatalf("a second new Mac: %v", err)
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

	// Rotation. Each case enrols at t0 and rotates a day later unless it says otherwise.
	rotation := t0.Add(24 * time.Hour)
	// rotateAt asks to rotate from's key to key at now, signed two seconds earlier. The new
	// key is a file key, so it can rotate again.
	rotateAt := func(s Store, tenant, from string, key []byte, now time.Time) (RotateResult, error) {
		id, err := NewDeviceID()
		if err != nil {
			return RotateResult{}, err
		}
		return s.Rotate(ctx, RotateRequest{
			TenantID: tenant, FromDeviceID: from, DeviceID: id, PublicKey: key, KeyStorage: KeyStorageSoftware,
			SignedAt: now.Add(-2 * time.Second), Now: now, Alert: alertAt(now),
		})
	}
	rotate := func(t *testing.T, s Store, tenant, from string, now time.Time) DeviceCredential {
		t.Helper()
		res, err := rotateAt(s, tenant, from, newKey(t), now)
		if err != nil || res.Retry || res.Contest != nil {
			t.Fatalf("rotate %s: %+v, %v", from, res, err)
		}
		return res.Credential
	}
	status := func(t *testing.T, s Store, id string) CredentialStatus {
		t.Helper()
		return lookup(t, s, id).Status
	}
	count := func(t *testing.T, s Store, tenant, serial string) int {
		t.Helper()
		creds, err := s.ListCredentials(ctx, tenant, CredentialFilter{Serial: serial})
		if err != nil {
			t.Fatal(err)
		}
		return len(creds)
	}
	staleKeyUsed := func(t *testing.T, s Store, id string, signedAt, now time.Time) *ContestResult {
		t.Helper()
		c, err := s.StaleKeyUsed(ctx, id, signedAt, now, alertAt(now))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	t.Run("rotate activates the new key and revokes the old", func(t *testing.T) {
		s, tenant, serial := setup(t)
		enrolled, err := s.Enroll(ctx, DeviceCredential{
			DeviceID: newUUID(t), TenantID: tenant, Serial: serial, HardwareUUID: "HW-1", PublicKey: newKey(t),
			KeyStorage: KeyStorageSoftware, Token: "token:1a2b3c4d", CreatedAt: t0,
		}, EnrollLimits{})
		if err != nil {
			t.Fatal(err)
		}
		old := enrolled.Credential
		key, id := newKey(t), newUUID(t)
		signedAt := rotation.Add(-3 * time.Second)
		res, err := s.Rotate(ctx, RotateRequest{
			TenantID: tenant, FromDeviceID: old.DeviceID, DeviceID: id, PublicKey: key,
			KeyStorage: KeyStorageSecureEnclave, SignedAt: signedAt, Now: rotation,
		})
		if err != nil || res.Retry || res.Contest != nil {
			t.Fatalf("rotate = %+v, %v", res, err)
		}
		if res.Previous.DeviceID != old.DeviceID || res.Previous.KeyStorage != KeyStorageSoftware {
			t.Fatalf("previous = %+v", res.Previous)
		}
		for name, c := range map[string]DeviceCredential{"result": res.Credential, "stored": lookup(t, s, id)} {
			if c.DeviceID != id || c.Status != CredentialActive || c.RotatedFrom != old.DeviceID || c.TenantID != tenant ||
				c.Serial != serial || c.HardwareUUID != "HW-1" || c.Token != "token:1a2b3c4d" || c.KeyStorage != KeyStorageSecureEnclave ||
				c.KeyFingerprint() != (DeviceCredential{PublicKey: key}).KeyFingerprint() {
				t.Fatalf("%s successor = %+v", name, c)
			}
			if !c.CreatedAt.Equal(rotation) || c.ActivatedAt == nil || !c.ActivatedAt.Equal(rotation) || c.RevokedAt != nil {
				t.Fatalf("%s successor times = %v %v %v", name, c.CreatedAt, c.ActivatedAt, c.RevokedAt)
			}
			if c.RotationSignedAt == nil || !c.RotationSignedAt.Equal(signedAt) {
				t.Fatalf("%s rotation signed at = %v", name, c.RotationSignedAt)
			}
		}
		prev := lookup(t, s, old.DeviceID)
		if prev.Status != CredentialRevoked || prev.RevokedAt == nil || !prev.RevokedAt.Equal(rotation) || prev.RotatedTo != id || prev.RotatedFrom != "" {
			t.Fatalf("old = %+v", prev)
		}
		list, err := s.ListCredentials(ctx, tenant, CredentialFilter{Serial: serial})
		if err != nil || len(list) != 2 || list[0].DeviceID != id || list[0].RotatedFrom != old.DeviceID || list[0].RotatedTo != "" ||
			list[1].DeviceID != old.DeviceID || list[1].RotatedTo != id {
			t.Fatalf("list = %+v, %v", list, err)
		}
	})

	t.Run("rotate retry returns the successor", func(t *testing.T) {
		s, tenant, serial := setup(t)
		old := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		key := newKey(t)
		first, err := rotateAt(s, tenant, old.DeviceID, key, rotation)
		if err != nil {
			t.Fatal(err)
		}
		// A retry comes before the rate limit, however soon or late it is.
		for _, at := range []time.Time{rotation.Add(time.Minute), rotation.Add(30 * 24 * time.Hour)} {
			again, err := rotateAt(s, tenant, old.DeviceID, key, at)
			if err != nil || !again.Retry || again.Contest != nil || again.Credential.DeviceID != first.Credential.DeviceID ||
				again.Credential.Status != CredentialActive || again.Previous.DeviceID != old.DeviceID {
				t.Fatalf("retry at %v = %+v, %v", at, again, err)
			}
		}
		if n := count(t, s, tenant, serial); n != 2 {
			t.Fatalf("%d credentials after retries, want 2", n)
		}
		// An admin revokes the successor; a retry still answers with it, as it now is.
		if _, err := s.RevokeCredential(ctx, tenant, first.Credential.DeviceID, rotation.Add(time.Hour), auditFor(t, tenant, AuditRevokeEnrollment)); err != nil {
			t.Fatal(err)
		}
		again, err := rotateAt(s, tenant, old.DeviceID, key, rotation.Add(2*time.Hour))
		if err != nil || !again.Retry || again.Credential.DeviceID != first.Credential.DeviceID || again.Credential.Status != CredentialRevoked {
			t.Fatalf("retry after the successor was revoked = %+v, %v", again, err)
		}
	})

	t.Run("rotating a stale key to another key is a contest", func(t *testing.T) {
		s, tenant, serial := setup(t)
		old := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		next := rotate(t, s, tenant, old.DeviceID, rotation)
		res, err := rotateAt(s, tenant, old.DeviceID, newKey(t), rotation.Add(time.Minute))
		if !errors.Is(err, ErrRotatedElsewhere) {
			t.Fatalf("err = %v, want %v", err, ErrRotatedElsewhere)
		}
		if res.Retry || res.Credential.DeviceID != "" || res.Previous.DeviceID != old.DeviceID || res.Contest == nil {
			t.Fatalf("result = %+v", res)
		}
		c := res.Contest
		if c.Stale.DeviceID != old.DeviceID || c.Stale.RotatedTo != next.DeviceID || c.Revoked == nil ||
			c.Revoked.DeviceID != next.DeviceID || c.Revoked.Status != CredentialRevoked || !c.Report {
			t.Fatalf("contest = %+v revoked = %+v", c, c.Revoked)
		}
		if got := lookup(t, s, next.DeviceID); got.Status != CredentialRevoked || !got.RevokedAt.Equal(rotation.Add(time.Minute)) {
			t.Fatalf("successor after the contest = %+v", got)
		}
		if n := count(t, s, tenant, serial); n != 2 {
			t.Fatalf("%d credentials, want 2: the contest stores no key", n)
		}
	})

	t.Run("rotating a pending key is refused", func(t *testing.T) {
		s, tenant, serial := setup(t)
		active := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		pending := enroll(t, s, tenant, serial, newKey(t), t0.Add(time.Hour)).Credential
		if pending.Status != CredentialPending {
			t.Fatalf("second key = %s, want pending", pending.Status)
		}
		res, err := rotateAt(s, tenant, pending.DeviceID, newKey(t), rotation.Add(time.Hour))
		if !errors.Is(err, ErrInvalidState) || res.Previous.DeviceID != pending.DeviceID || res.Previous.Status != CredentialPending {
			t.Fatalf("rotate a pending key = %+v, %v", res, err)
		}
		if n := count(t, s, tenant, serial); n != 2 || status(t, s, active.DeviceID) != CredentialActive || status(t, s, pending.DeviceID) != CredentialPending {
			t.Fatalf("something changed: %d credentials", n)
		}
	})

	t.Run("rotating a revoked key is refused", func(t *testing.T) {
		s, tenant, serial := setup(t)
		old := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		if _, err := s.RevokeCredential(ctx, tenant, old.DeviceID, t0.Add(time.Hour), auditFor(t, tenant, AuditRevokeEnrollment)); err != nil {
			t.Fatal(err)
		}
		if _, err := rotateAt(s, tenant, old.DeviceID, newKey(t), rotation); !errors.Is(err, ErrRevoked) {
			t.Fatalf("rotate a revoked key: err = %v, want %v", err, ErrRevoked)
		}
		if n := count(t, s, tenant, serial); n != 1 {
			t.Fatalf("%d credentials, want 1", n)
		}
		// An unknown key, or one in another tenant, is not found.
		if _, err := rotateAt(s, tenant, newUUID(t), newKey(t), rotation); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rotate an unknown key: err = %v", err)
		}
		if _, err := rotateAt(s, tenant, "not-a-uuid", newKey(t), rotation); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rotate a malformed ID: err = %v", err)
		}
		other := enroll(t, s, tenant, serial+"X", newKey(t), t0).Credential
		if _, err := rotateAt(s, tenant+"-other", other.DeviceID, newKey(t), rotation); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rotate from another tenant: err = %v", err)
		}
	})

	t.Run("rotating to a key in use is refused", func(t *testing.T) {
		s, tenant, serial := setup(t)
		old := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		here, elsewhere := newKey(t), newKey(t)
		enroll(t, s, tenant, serial+"X", here, t0)
		enroll(t, s, tenant+"-other", serial, elsewhere, t0)
		for name, key := range map[string][]byte{"this tenant": here, "another tenant": elsewhere} {
			if _, err := rotateAt(s, tenant, old.DeviceID, key, rotation); !errors.Is(err, ErrKeyInUse) {
				t.Fatalf("%s: err = %v, want %v", name, err, ErrKeyInUse)
			}
		}
		if status(t, s, old.DeviceID) != CredentialActive || count(t, s, tenant, serial) != 1 {
			t.Fatal("a refused rotation changed the key")
		}
	})

	t.Run("a Secure Enclave key is not rotated", func(t *testing.T) {
		s, tenant, serial := setup(t)
		res, err := s.Enroll(ctx, DeviceCredential{
			DeviceID: newUUID(t), TenantID: tenant, Serial: serial, HardwareUUID: "HW", PublicKey: newKey(t),
			KeyStorage: KeyStorageSecureEnclave, CreatedAt: t0,
		}, EnrollLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rotateAt(s, tenant, res.Credential.DeviceID, newKey(t), rotation); !errors.Is(err, ErrRotationNotAllowed) {
			t.Fatalf("err = %v, want %v", err, ErrRotationNotAllowed)
		}
		if status(t, s, res.Credential.DeviceID) != CredentialActive || count(t, s, tenant, serial) != 1 {
			t.Fatal("a refused rotation changed the key")
		}
	})

	t.Run("rotating within a day is refused", func(t *testing.T) {
		s, tenant, serial := setup(t)
		old := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		res, err := rotateAt(s, tenant, old.DeviceID, newKey(t), t0.Add(23*time.Hour+59*time.Minute))
		if !errors.Is(err, ErrRotationTooSoon) || res.Previous.ActivatedAt == nil || !res.Previous.ActivatedAt.Equal(t0) {
			t.Fatalf("at 23h59m = %+v, %v", res, err)
		}
		if status(t, s, old.DeviceID) != CredentialActive || count(t, s, tenant, serial) != 1 {
			t.Fatal("a refused rotation changed the key")
		}
		rotate(t, s, tenant, old.DeviceID, t0.Add(24*time.Hour))

		// A key with no activation time counts as activated long ago.
		other := enroll(t, s, tenant, serial+"X", newKey(t), t0).Credential
		clearActivatedAt(t, s, other.DeviceID)
		rotate(t, s, tenant, other.DeviceID, t0.Add(time.Minute))
	})

	t.Run("revoking a rotated key names the key in use", func(t *testing.T) {
		s, tenant, serial := setup(t)
		a := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		b := rotate(t, s, tenant, a.DeviceID, rotation)
		c := rotate(t, s, tenant, b.DeviceID, rotation.Add(24*time.Hour))
		auditBefore, err := s.ListAudit(ctx, tenant, AuditFilter{})
		if err != nil {
			t.Fatal(err)
		}
		before, err := s.ListCredentials(ctx, tenant, CredentialFilter{})
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{a.DeviceID, b.DeviceID} {
			if _, err := s.RevokeCredential(ctx, tenant, id, rotation.Add(48*time.Hour), auditFor(t, tenant, AuditRevokeEnrollment)); !errors.Is(err, ErrRotated) {
				t.Fatalf("revoke a rotated key: err = %v, want %v", err, ErrRotated)
			}
			if in, err := s.LineageActive(ctx, id); err != nil || in.DeviceID != c.DeviceID {
				t.Fatalf("lineage of %s: %+v, %v; want %s", id, in, err, c.DeviceID)
			}
		}
		if in, err := s.LineageActive(ctx, c.DeviceID); err != nil || in.DeviceID != c.DeviceID {
			t.Fatalf("an active key's lineage: %+v, %v", in, err)
		}
		after, err := s.ListCredentials(ctx, tenant, CredentialFilter{})
		if err != nil || keyStates(after) != keyStates(before) {
			t.Fatalf("refused revokes changed keys:\n%s\n%s, %v", keyStates(before), keyStates(after), err)
		}
		if audit, err := s.ListAudit(ctx, tenant, AuditFilter{}); err != nil || len(audit) != len(auditBefore) {
			t.Fatalf("refused revokes wrote %d audit entries, %v", len(audit)-len(auditBefore), err)
		}

		// Once the key in use is revoked, the old ones are just revoked keys.
		if _, err := s.RevokeCredential(ctx, tenant, c.DeviceID, rotation.Add(49*time.Hour), auditFor(t, tenant, AuditRevokeEnrollment)); err != nil {
			t.Fatal(err)
		}
		got, err := s.RevokeCredential(ctx, tenant, a.DeviceID, rotation.Add(50*time.Hour), auditFor(t, tenant, AuditRevokeEnrollment))
		if err != nil || got.Status != CredentialRevoked || !got.RevokedAt.Equal(rotation) {
			t.Fatalf("revoke the first key after = %+v, %v", got, err)
		}
		if _, err := s.LineageActive(ctx, a.DeviceID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a lineage with nothing active: err = %v", err)
		}
		if _, err := s.LineageActive(ctx, newUUID(t)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("an unknown key's lineage: err = %v", err)
		}
	})

	t.Run("approving a rotated key is refused", func(t *testing.T) {
		s, tenant, serial := setup(t)
		a := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		b := rotate(t, s, tenant, a.DeviceID, rotation)
		if _, err := s.ApproveCredential(ctx, tenant, a.DeviceID, rotation.Add(time.Hour), auditFor(t, tenant, AuditApproveEnrollment)); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("err = %v, want %v", err, ErrInvalidState)
		}
		if status(t, s, a.DeviceID) != CredentialRevoked || status(t, s, b.DeviceID) != CredentialActive {
			t.Fatal("a refused approval changed the keys")
		}
	})

	t.Run("a stale key's use is a contest once", func(t *testing.T) {
		s, tenant, serial := setup(t)
		a := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		b := rotate(t, s, tenant, a.DeviceID, rotation)
		c := staleKeyUsed(t, s, a.DeviceID, rotation.Add(time.Minute), rotation.Add(2*time.Minute))
		if c == nil || c.Stale.DeviceID != a.DeviceID || c.Stale.RotatedTo != b.DeviceID || c.Revoked == nil ||
			c.Revoked.DeviceID != b.DeviceID || !c.Report {
			t.Fatalf("first use = %+v", c)
		}
		if got := lookup(t, s, b.DeviceID); got.Status != CredentialRevoked || !got.RevokedAt.Equal(rotation.Add(2*time.Minute)) {
			t.Fatalf("successor after the contest = %+v", got)
		}
		// The same day, nothing more is revoked or reported.
		c = staleKeyUsed(t, s, a.DeviceID, rotation.Add(3*time.Hour), rotation.Add(3*time.Hour))
		if c == nil || c.Revoked != nil || c.Report {
			t.Fatalf("second use the same day = %+v", c)
		}
		// A day on, it is reported again.
		c = staleKeyUsed(t, s, a.DeviceID, rotation.Add(25*time.Hour), rotation.Add(25*time.Hour))
		if c == nil || c.Revoked != nil || !c.Report {
			t.Fatalf("use a day later = %+v", c)
		}
		// A revoked key with no successor is not stale, and an unknown one is not found.
		if c := staleKeyUsed(t, s, b.DeviceID, rotation.Add(26*time.Hour), rotation.Add(26*time.Hour)); c != nil {
			t.Fatalf("a key with no successor = %+v", c)
		}
		if _, err := s.StaleKeyUsed(ctx, newUUID(t), rotation, rotation, alertAt(rotation)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("an unknown key: err = %v", err)
		}
	})

	t.Run("an in-flight request is exempt", func(t *testing.T) {
		s, tenant, serial := setup(t)
		a := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		b := rotate(t, s, tenant, a.DeviceID, rotation)
		signed := *lookup(t, s, b.DeviceID).RotationSignedAt
		for _, at := range []struct{ signed, now time.Time }{
			{signed, rotation.Add(InFlightGrace)},
			{signed.Add(-time.Minute), rotation.Add(30 * time.Second)},
		} {
			if c := staleKeyUsed(t, s, a.DeviceID, at.signed, at.now); c != nil {
				t.Fatalf("signed %v, received %v: contest %+v", at.signed, at.now, c)
			}
		}
		if status(t, s, b.DeviceID) != CredentialActive {
			t.Fatal("an in-flight request revoked the successor")
		}
		c := staleKeyUsed(t, s, a.DeviceID, signed, rotation.Add(InFlightGrace+time.Second))
		if c == nil || c.Revoked == nil || c.Revoked.DeviceID != b.DeviceID || !c.Report {
			t.Fatalf("received after the grace = %+v", c)
		}
		// Signed after the rotation, within the grace, is a contest too.
		s2, tenant2, serial2 := setup(t)
		a2 := enroll(t, s2, tenant2, serial2, newKey(t), t0).Credential
		b2 := rotate(t, s2, tenant2, a2.DeviceID, rotation)
		signed2 := *lookup(t, s2, b2.DeviceID).RotationSignedAt
		if c := staleKeyUsed(t, s2, a2.DeviceID, signed2.Add(time.Second), rotation.Add(time.Second)); c == nil || c.Revoked == nil {
			t.Fatalf("signed after the rotation = %+v", c)
		}
	})

	t.Run("a stale key past the contest window only alerts", func(t *testing.T) {
		for _, tc := range []struct {
			after   time.Duration
			revokes bool
		}{{31 * 24 * time.Hour, false}, {29 * 24 * time.Hour, true}} {
			s, tenant, serial := setup(t)
			a := enroll(t, s, tenant, serial, newKey(t), t0).Credential
			b := rotate(t, s, tenant, a.DeviceID, rotation)
			at := rotation.Add(tc.after)
			c := staleKeyUsed(t, s, a.DeviceID, at, at)
			if c == nil || !c.Report || (c.Revoked != nil) != tc.revokes {
				t.Fatalf("after %v: contest = %+v", tc.after, c)
			}
			if want := map[bool]CredentialStatus{true: CredentialRevoked, false: CredentialActive}[tc.revokes]; status(t, s, b.DeviceID) != want {
				t.Fatalf("after %v: successor = %s, want %s", tc.after, status(t, s, b.DeviceID), want)
			}
		}
	})

	t.Run("an old backup revokes once per lineage", func(t *testing.T) {
		s, tenant, serial := setup(t)
		a := enroll(t, s, tenant, serial, newKey(t), t0).Credential
		rotate(t, s, tenant, a.DeviceID, rotation)
		if c := staleKeyUsed(t, s, a.DeviceID, rotation.Add(time.Minute), rotation.Add(2*time.Minute)); c == nil || c.Revoked == nil || !c.Report {
			t.Fatalf("first contest = %+v", c)
		}
		// The Mac enrols afresh and an admin approves it: a new lineage.
		d := enroll(t, s, tenant, serial, newKey(t), rotation.Add(time.Hour)).Credential
		if _, err := s.ApproveCredential(ctx, tenant, d.DeviceID, rotation.Add(2*time.Hour), auditFor(t, tenant, AuditApproveEnrollment)); err != nil {
			t.Fatal(err)
		}
		c := staleKeyUsed(t, s, a.DeviceID, rotation.Add(3*time.Hour), rotation.Add(3*time.Hour))
		if c == nil || c.Revoked != nil || c.Report {
			t.Fatalf("the same day = %+v", c)
		}
		c = staleKeyUsed(t, s, a.DeviceID, rotation.Add(27*time.Hour), rotation.Add(27*time.Hour))
		if c == nil || c.Revoked != nil || !c.Report {
			t.Fatalf("a new day = %+v", c)
		}
		if status(t, s, d.DeviceID) != CredentialActive {
			t.Fatal("an old backup revoked a new lineage")
		}
	})

	t.Run("rotated keys do not count towards keys per Mac", func(t *testing.T) {
		s, tenant, serial := setup(t)
		limits := EnrollLimits{KeysPerMacPerDay: 2}
		a, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0, limits)
		if err != nil {
			t.Fatal(err)
		}
		b := rotate(t, s, tenant, a.Credential.DeviceID, t0.Add(25*time.Hour))
		rotate(t, s, tenant, b.DeviceID, t0.Add(49*time.Hour))
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(49*time.Hour+time.Minute), limits); err != nil {
			t.Fatalf("a key after two rotations: %v", err)
		}
		// Counting the rotated key, this would be the third in the day.
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(49*time.Hour+2*time.Minute), limits); err != nil {
			t.Fatalf("a second enrolled key in the day: %v", err)
		}
		if _, err := enrollLimited(s, tenant, serial, "HW", newKey(t), t0.Add(49*time.Hour+3*time.Minute), limits); !errors.Is(err, ErrKeysPerMacLimited) {
			t.Fatalf("a third enrolled key in the day: err = %v, want %v", err, ErrKeysPerMacLimited)
		}
	})
}

// keyStates describes each credential's status and times, to compare before and after.
func keyStates(cs []DeviceCredential) string {
	at := func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	out := ""
	for _, c := range cs {
		out += fmt.Sprintf("%s %s %s %s %s; ", c.DeviceID, c.Status, at(c.ActivatedAt), at(c.RevokedAt), c.RotatedTo)
	}
	return out
}

// clearActivatedAt makes an active key look as if its activation time was never recorded.
func clearActivatedAt(t *testing.T, s Store, deviceID string) {
	t.Helper()
	switch s := s.(type) {
	case *Memory:
		s.mu.Lock()
		defer s.mu.Unlock()
		c := s.creds[deviceID]
		c.ActivatedAt = nil
		s.creds[deviceID] = c
	case *Postgres:
		if _, err := s.pool.Exec(context.Background(), `UPDATE device_credentials SET activated_at = NULL WHERE device_id = $1`, deviceID); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("clearActivatedAt: unknown store %T", s)
	}
}

// TestPostgresRefusesNewMacsWithoutTheTenantLock checks that a new Mac over the limit is
// refused without waiting for the tenant's new-Mac lock, so a flood of refused serials
// doesn't queue on it, and that a new Mac with room still waits for it.
func TestPostgresRefusesNewMacsWithoutTheTenantLock(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	p, err := OpenPostgres(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")
	tenant := "tenant-" + randomHex(t)
	enrol := func(ctx context.Context, limits EnrollLimits) error {
		sn := "C02LOCK" + randomHex(t)
		_, err := p.Enroll(ctx, DeviceCredential{
			DeviceID: newUUID(t), TenantID: tenant, Serial: sn, HardwareUUID: "HW-" + sn, PublicKey: newKey(t), CreatedAt: t0,
		}, limits)
		return err
	}
	for i := 0; i < 2; i++ {
		if err := enrol(ctx, EnrollLimits{NewMacsPerHour: 2}); err != nil {
			t.Fatalf("Mac %d: %v", i+1, err)
		}
	}

	// Another enrolment holds the tenant's lock.
	holder, err := p.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if err := lockTenantNewMacs(ctx, holder, tenant); err != nil {
		t.Fatal(err)
	}

	short, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := enrol(short, EnrollLimits{NewMacsPerHour: 2}); !errors.Is(err, ErrNewMacsLimited) {
		t.Fatalf("over the limit while the lock is held = %v, want %v", err, ErrNewMacsLimited)
	}

	done := make(chan error, 1)
	go func() { done <- enrol(ctx, EnrollLimits{NewMacsPerHour: 5}) }()
	select {
	case err := <-done:
		t.Fatalf("with room, enrolled without waiting for the lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("with room, after the lock is released: %v", err)
	}
}

// TestPostgresRevokeWinsOverConcurrentApproval checks that a revoke answered with success
// leaves the key revoked, however it races an approval of the same key, and that the
// Mac never ends with two active keys.
func TestPostgresRevokeWinsOverConcurrentApproval(t *testing.T) {
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	p, err := OpenPostgres(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")
	tenant := "tenant-" + randomHex(t)
	for i := 0; i < 30; i++ {
		serial := "C02RACE" + randomHex(t)
		enrol := func(hardware string, at time.Time) DeviceCredential {
			t.Helper()
			res, err := p.Enroll(ctx, DeviceCredential{
				DeviceID: newUUID(t), TenantID: tenant, Serial: serial, HardwareUUID: hardware, PublicKey: newKey(t), CreatedAt: at,
			}, EnrollLimits{})
			if err != nil {
				t.Fatal(err)
			}
			return res.Credential
		}
		enrol("HW-A", t0)
		b := enrol("HW-B", t0.Add(time.Hour))
		if b.Status != CredentialPending {
			t.Fatalf("run %d: key from other hardware = %s, want pending", i, b.Status)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		var approveErr, revokeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, approveErr = p.ApproveCredential(ctx, tenant, b.DeviceID, t0.Add(2*time.Hour), auditFor(t, tenant, AuditApproveEnrollment))
		}()
		go func() {
			defer wg.Done()
			<-start
			_, revokeErr = p.RevokeCredential(ctx, tenant, b.DeviceID, t0.Add(2*time.Hour), auditFor(t, tenant, AuditRevokeEnrollment))
		}()
		close(start)
		wg.Wait()

		if revokeErr != nil {
			t.Fatalf("run %d: revoke = %v", i, revokeErr)
		}
		if approveErr != nil && !errors.Is(approveErr, ErrInvalidState) {
			t.Fatalf("run %d: approve = %v", i, approveErr)
		}
		got, err := p.Credential(ctx, b.DeviceID)
		if err != nil || got.Status != CredentialRevoked {
			t.Fatalf("run %d: after a successful revoke, the key = %s, %v (approve = %v)", i, got.Status, err, approveErr)
		}
		active, err := p.ListCredentials(ctx, tenant, CredentialFilter{Status: CredentialActive, Serial: serial})
		if err != nil || len(active) > 1 {
			t.Fatalf("run %d: %d active keys, %v", i, len(active), err)
		}
	}
}

// openTestPostgres opens the test database, or skips without one.
func openTestPostgres(t *testing.T) *Postgres {
	t.Helper()
	url := os.Getenv("ALTIWARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ALTIWARD_TEST_DATABASE_URL not set")
	}
	p, err := OpenPostgres(context.Background(), url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// rotateRequest asks to rotate from's key to a new key at now.
func rotateRequest(t *testing.T, tenant, from string, key []byte, now time.Time) RotateRequest {
	t.Helper()
	return RotateRequest{
		TenantID: tenant, FromDeviceID: from, DeviceID: newUUID(t), PublicKey: key,
		KeyStorage: KeyStorageSecureEnclave, SignedAt: now.Add(-time.Second), Now: now, Alert: alertAt(now),
	}
}

// alertAt makes a contest's rotated_key_used event, raised at at, as the API does.
func alertAt(at time.Time) ContestAlert {
	return func(c ContestResult) event.Event {
		id, _ := NewDeviceID()
		detail := map[string]any{
			"state": event.EnrollmentStateRotatedKeyUsed, "device_id": c.Stale.DeviceID, "rotated_to": c.Stale.RotatedTo,
		}
		if c.Revoked != nil {
			detail["revoked_device_id"] = c.Revoked.DeviceID
		}
		return event.Event{
			SchemaVersion: event.SchemaVersion, EventID: id, Type: event.AgentEnrollment, Timestamp: at.UTC(),
			Device: event.Device{Serial: c.Stale.Serial, HardwareUUID: c.Stale.HardwareUUID}, Detail: detail,
		}
	}
}

// contestAlertSuite checks that a contest that reports stores its alert with it, queued for
// export like any event, and that one that doesn't report stores none.
func contestAlertSuite(t *testing.T, newStore func(t *testing.T, sink string) Store) {
	ctx := context.Background()
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")
	rotation := t0.Add(24 * time.Hour)
	// stale enrols a Mac and rotates its key, returning the store, the export sink, the
	// replaced key and its successor.
	stale := func(t *testing.T) (Store, string, DeviceCredential, DeviceCredential) {
		sink := "sink-" + randomHex(t)
		s := newStore(t, sink)
		old := enrolFirst(t, s, "tenant-"+randomHex(t), "C02"+randomHex(t), "HW", t0)
		res, err := s.Rotate(ctx, rotateRequest(t, old.TenantID, old.DeviceID, newKey(t), rotation))
		if err != nil {
			t.Fatal(err)
		}
		return s, sink, old, res.Credential
	}
	// alerts returns the tenant's rotated_key_used events queued for export since the last
	// call, and marks them delivered.
	alerts := func(t *testing.T, s Store, sink, tenant string, now time.Time) []event.Event {
		t.Helper()
		queued, err := s.ClaimExports(ctx, sink, 100, time.Minute, now)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]int64, len(queued))
		for i, item := range queued {
			ids[i] = item.ID
		}
		if err := s.CompleteExports(ctx, ids, now); err != nil {
			t.Fatal(err)
		}
		var out []event.Event
		for _, item := range queued {
			if item.TenantID == tenant && item.Event.Type == event.AgentEnrollment &&
				item.Event.Detail["state"] == event.EnrollmentStateRotatedKeyUsed {
				out = append(out, item.Event.Event)
			}
		}
		return out
	}

	t.Run("a stale key's use stores its alert", func(t *testing.T) {
		s, sink, old, next := stale(t)
		at := rotation.Add(2 * time.Minute)
		c, err := s.StaleKeyUsed(ctx, old.DeviceID, at, at, alertAt(at))
		if err != nil || c == nil || !c.Report || c.Revoked == nil {
			t.Fatalf("contest = %+v, %v", c, err)
		}
		got := alerts(t, s, sink, old.TenantID, at)
		if len(got) != 1 || got[0].Detail["device_id"] != old.DeviceID || got[0].Detail["revoked_device_id"] != next.DeviceID {
			t.Fatalf("alerts = %+v", got)
		}
		// A use the same day reports nothing, so its alert isn't even made.
		later := at.Add(time.Hour)
		called := false
		c, err = s.StaleKeyUsed(ctx, old.DeviceID, later, later, func(c ContestResult) event.Event {
			called = true
			return alertAt(later)(c)
		})
		if err != nil || c == nil || c.Report || called {
			t.Fatalf("the same day: contest = %+v, %v, alert made: %v", c, err, called)
		}
		if got := alerts(t, s, sink, old.TenantID, later.Add(time.Hour)); len(got) != 0 {
			t.Fatalf("alerts the same day = %+v", got)
		}
	})

	t.Run("a stale key's rotation stores its alert", func(t *testing.T) {
		s, sink, old, next := stale(t)
		at := rotation.Add(2 * time.Minute)
		res, err := s.Rotate(ctx, rotateRequest(t, old.TenantID, old.DeviceID, newKey(t), at))
		if !errors.Is(err, ErrRotatedElsewhere) || res.Contest == nil || !res.Contest.Report {
			t.Fatalf("rotate = %+v, %v", res, err)
		}
		got := alerts(t, s, sink, old.TenantID, at)
		if len(got) != 1 || got[0].Detail["device_id"] != old.DeviceID || got[0].Detail["revoked_device_id"] != next.DeviceID {
			t.Fatalf("alerts = %+v", got)
		}
	})
}

// TestPostgresContestUndoneWhenItsAlertFails checks that a contest whose alert can't be
// stored changes nothing, so the stale key's next use contests, revokes and reports.
func TestPostgresContestUndoneWhenItsAlertFails(t *testing.T) {
	p := openTestPostgres(t)
	ctx := context.Background()
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")
	rotation := t0.Add(24 * time.Hour)
	// The events table refuses an event ID that isn't a UUID, as it would refuse any write
	// when the database fails.
	failing := func(at time.Time) ContestAlert {
		return func(c ContestResult) event.Event {
			e := alertAt(at)(c)
			e.EventID = "not-a-uuid"
			return e
		}
	}
	for _, path := range []string{"use", "rotation"} {
		t.Run(path, func(t *testing.T) {
			old := enrolFirst(t, p, "tenant-"+randomHex(t), "C02"+randomHex(t), "HW", t0)
			res, err := p.Rotate(ctx, rotateRequest(t, old.TenantID, old.DeviceID, newKey(t), rotation))
			if err != nil {
				t.Fatal(err)
			}
			next := res.Credential
			contest := func(at time.Time, alert ContestAlert) (*ContestResult, error) {
				if path == "use" {
					return p.StaleKeyUsed(ctx, old.DeviceID, at, at, alert)
				}
				req := rotateRequest(t, old.TenantID, old.DeviceID, newKey(t), at)
				req.Alert = alert
				res, err := p.Rotate(ctx, req)
				if errors.Is(err, ErrRotatedElsewhere) {
					err = nil
				}
				return res.Contest, err
			}

			at := rotation.Add(2 * time.Minute)
			if c, err := contest(at, failing(at)); err == nil || errors.Is(err, ErrRotatedElsewhere) {
				t.Fatalf("contest with a failing alert = %+v, %v; want an error", c, err)
			}
			if got, err := p.Credential(ctx, next.DeviceID); err != nil || got.Status != CredentialActive {
				t.Fatalf("successor after a failed contest = %+v, %v", got, err)
			}
			// Nothing marked the use as reported: the next one, the same day, does it all.
			at = at.Add(time.Minute)
			c, err := contest(at, alertAt(at))
			if err != nil || c == nil || !c.Report || c.Revoked == nil || c.Revoked.DeviceID != next.DeviceID {
				t.Fatalf("the next use = %+v, %v", c, err)
			}
		})
	}
}

// enrolFirst enrols a serial's first key, which is active.
func enrolFirst(t *testing.T, s Store, tenant, serial, hardware string, at time.Time) DeviceCredential {
	t.Helper()
	res, err := s.Enroll(context.Background(), DeviceCredential{
		DeviceID: newUUID(t), TenantID: tenant, Serial: serial, HardwareUUID: hardware, PublicKey: newKey(t), CreatedAt: at,
	}, EnrollLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Credential
}

// TestPostgresConcurrentRotationsFromOneKey checks that one key rotated to many keys at once
// rotates once, and that each other attempt is a contest, of which exactly one revokes.
func TestPostgresConcurrentRotationsFromOneKey(t *testing.T) {
	p := openTestPostgres(t)
	ctx := context.Background()
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")
	tenant, serial := "tenant-"+randomHex(t), "C02ROT"+randomHex(t)
	old := enrolFirst(t, p, tenant, serial, "HW", t0)

	const attempts = 20
	reqs := make([]RotateRequest, attempts)
	for i := range reqs {
		reqs[i] = rotateRequest(t, tenant, old.DeviceID, newKey(t), t0.Add(24*time.Hour))
	}
	results, errs := make([]RotateResult, attempts), make([]error, attempts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = p.Rotate(ctx, reqs[i])
		}()
	}
	close(start)
	wg.Wait()

	rotated, elsewhere, revoking := 0, 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			rotated++
		case errors.Is(err, ErrRotatedElsewhere):
			elsewhere++
			if c := results[i].Contest; c == nil {
				t.Fatalf("attempt %d: no contest", i)
			} else if c.Revoked != nil {
				revoking++
				if !c.Report {
					t.Fatalf("attempt %d revoked without a report", i)
				}
			} else if c.Report {
				t.Fatalf("attempt %d reported again the same day", i)
			}
		default:
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if rotated != 1 || elsewhere != attempts-1 || revoking != 1 {
		t.Fatalf("%d rotated, %d rotated elsewhere, %d revoked; want 1, %d, 1", rotated, elsewhere, revoking, attempts-1)
	}
	if active, err := p.ListCredentials(ctx, tenant, CredentialFilter{Serial: serial, Status: CredentialActive}); err != nil || len(active) != 0 {
		t.Fatalf("%d active keys afterwards, %v", len(active), err)
	}
}

// TestPostgresRotationRacesRevoke checks that a revoke answered with success leaves nothing
// active in the key's lineage, however it races a rotation, and that otherwise it names the
// rotation.
func TestPostgresRotationRacesRevoke(t *testing.T) {
	p := openTestPostgres(t)
	ctx := context.Background()
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")
	tenant := "tenant-" + randomHex(t)
	for i := 0; i < 30; i++ {
		old := enrolFirst(t, p, tenant, "C02RACE"+randomHex(t), "HW", t0)
		req := rotateRequest(t, tenant, old.DeviceID, newKey(t), t0.Add(24*time.Hour))
		start := make(chan struct{})
		var wg sync.WaitGroup
		var rotateErr, revokeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, rotateErr = p.Rotate(ctx, req)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, revokeErr = p.RevokeCredential(ctx, tenant, old.DeviceID, t0.Add(24*time.Hour), auditFor(t, tenant, AuditRevokeEnrollment))
		}()
		close(start)
		wg.Wait()

		active, lineageErr := p.LineageActive(ctx, old.DeviceID)
		switch {
		case revokeErr == nil:
			if !errors.Is(rotateErr, ErrRevoked) || !errors.Is(lineageErr, ErrNotFound) {
				t.Fatalf("run %d: revoked, then rotate = %v and the lineage's active key = %+v, %v", i, rotateErr, active, lineageErr)
			}
		case errors.Is(revokeErr, ErrRotated):
			if rotateErr != nil || lineageErr != nil || active.DeviceID != req.DeviceID {
				t.Fatalf("run %d: rotated, then rotate = %v and the lineage's active key = %+v, %v", i, rotateErr, active, lineageErr)
			}
		default:
			t.Fatalf("run %d: revoke = %v", i, revokeErr)
		}
	}
}

// TestPostgresRotationRacesApproval checks that approving a pending key while the active key
// rotates leaves the approved key active and nothing else.
func TestPostgresRotationRacesApproval(t *testing.T) {
	p := openTestPostgres(t)
	ctx := context.Background()
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")
	tenant := "tenant-" + randomHex(t)
	for i := 0; i < 30; i++ {
		serial := "C02RACE" + randomHex(t)
		old := enrolFirst(t, p, tenant, serial, "HW-A", t0)
		pending, err := p.Enroll(ctx, DeviceCredential{
			DeviceID: newUUID(t), TenantID: tenant, Serial: serial, HardwareUUID: "HW-B", PublicKey: newKey(t), CreatedAt: t0.Add(time.Hour),
		}, EnrollLimits{})
		if err != nil || pending.Credential.Status != CredentialPending {
			t.Fatalf("run %d: pending = %+v, %v", i, pending.Credential, err)
		}
		req := rotateRequest(t, tenant, old.DeviceID, newKey(t), t0.Add(24*time.Hour))
		start := make(chan struct{})
		var wg sync.WaitGroup
		var rotateErr, approveErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, rotateErr = p.Rotate(ctx, req)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, approveErr = p.ApproveCredential(ctx, tenant, pending.Credential.DeviceID, t0.Add(24*time.Hour), auditFor(t, tenant, AuditApproveEnrollment))
		}()
		close(start)
		wg.Wait()

		if approveErr != nil {
			t.Fatalf("run %d: approve = %v", i, approveErr)
		}
		if rotateErr != nil && !errors.Is(rotateErr, ErrRevoked) {
			t.Fatalf("run %d: rotate = %v", i, rotateErr)
		}
		active, err := p.ListCredentials(ctx, tenant, CredentialFilter{Serial: serial, Status: CredentialActive})
		if err != nil || len(active) != 1 || active[0].DeviceID != pending.Credential.DeviceID {
			t.Fatalf("run %d: active keys = %+v, %v; want only the approved one", i, active, err)
		}
	}
}

// TestPostgresRotationLosesToAConcurrentEnrolmentOfTheSameKey checks that a rotation to a key
// that an enrolment is adding at the same moment is refused as a key in use, not with the
// database's unique violation.
func TestPostgresRotationLosesToAConcurrentEnrolmentOfTheSameKey(t *testing.T) {
	p := openTestPostgres(t)
	ctx := context.Background()
	t0 := testfixture.Time(t, "2026-10-16T12:00:00Z")
	tenant, serial := "tenant-"+randomHex(t), "C02ROT"+randomHex(t)
	old := enrolFirst(t, p, tenant, serial, "HW", t0)
	key := newKey(t)

	// An enrolment of the key, on another Mac, has inserted it and not yet committed.
	enrolment, err := p.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = enrolment.Rollback(ctx) }()
	if _, err := enrolment.Exec(ctx, `
		INSERT INTO device_credentials (device_id, tenant_id, serial, hardware_uuid, public_key, key_digest, status, created_at, activated_at)
		VALUES ($1, $2, $3, 'HW-OTHER', $4, $5, 'active', $6, $6)`,
		newUUID(t), tenant, "C02OTHER"+randomHex(t), key, keyDigest(key), t0); err != nil {
		t.Fatal(err)
	}

	req := rotateRequest(t, tenant, old.DeviceID, key, t0.Add(24*time.Hour))
	done := make(chan error, 1)
	go func() {
		_, err := p.Rotate(ctx, req)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the rotation finished before the enrolment committed: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := enrolment.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("rotate = %v, want %v", err, ErrKeyInUse)
	}
	if c, err := p.Credential(ctx, old.DeviceID); err != nil || c.Status != CredentialActive || c.RotatedTo != "" {
		t.Fatalf("the old key after a refused rotation = %+v, %v", c, err)
	}
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
