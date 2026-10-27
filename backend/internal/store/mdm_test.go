package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward/backend/internal/testfixture"
)

// mdmSuite checks the copy of the Macs an MDM manages, and the record of its sync.
func mdmSuite(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()
	t0 := testfixture.Time(t, "2026-10-27T12:00:00Z")
	setup := func(t *testing.T) (Store, string) { return newStore(t), "tenant-" + randomHex(t) }
	mac := func(id, serial string, seen time.Time) MDMDevice {
		return MDMDevice{DeviceID: id, Serial: serial, EntraDeviceID: "entra-" + id, PrimaryUPN: "jdoe@example.com",
			Name: "Mac " + serial, LastCheckIn: seen}
	}
	replace := func(t *testing.T, s Store, tenant, source string, at time.Time, devices ...MDMDevice) {
		t.Helper()
		if err := s.ReplaceMDMDevices(ctx, tenant, source, devices, at); err != nil {
			t.Fatal(err)
		}
	}
	// byID lists the copy by device ID, checking each record names its tenant and source.
	byID := func(t *testing.T, s Store, tenant, source string) map[string]MDMDevice {
		t.Helper()
		got, err := s.MDMDevices(ctx, tenant, source)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]MDMDevice{}
		for _, d := range got {
			if d.TenantID != tenant || d.Source != source {
				t.Fatalf("record names %s/%s, want %s/%s", d.TenantID, d.Source, tenant, source)
			}
			out[d.DeviceID] = d
		}
		return out
	}
	status := func(t *testing.T, s Store, tenant, source string) MDMSync {
		t.Helper()
		st, err := s.MDMSyncStatus(ctx, tenant, source)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	same := func(a, b MDMDevice) bool {
		return a.DeviceID == b.DeviceID && a.Serial == b.Serial && a.EntraDeviceID == b.EntraDeviceID &&
			a.PrimaryUPN == b.PrimaryUPN && a.Name == b.Name && a.LastCheckIn.Equal(b.LastCheckIn)
	}
	at := func(p *time.Time, want time.Time) bool { return p != nil && p.Equal(want) }

	t.Run("replaceSwapsTheWholeSet", func(t *testing.T) {
		s, tenant := setup(t)
		a := mac("0A1B2C3D-0000-4000-8000-00000000000A", "C02AAA", t0.Add(-time.Hour))
		b := mac("0a1b2c3d-0000-4000-8000-00000000000b", "C02BBB", t0.Add(-2*time.Hour))
		replace(t, s, tenant, MDMIntune, t0, a, b)
		got := byID(t, s, tenant, MDMIntune)
		lowered := a
		lowered.DeviceID = "0a1b2c3d-0000-4000-8000-00000000000a"
		if len(got) != 2 || !same(got[lowered.DeviceID], lowered) || !same(got[b.DeviceID], b) {
			t.Fatalf("first copy = %+v", got)
		}

		// The next sync drops a, changes b and adds c, which has never checked in. One ID
		// listed twice, in either case, is kept once, as last listed.
		b.Name, b.LastCheckIn = "Renamed", t0
		c := mac("0a1b2c3d-0000-4000-8000-00000000000c", "C02CCC", time.Time{})
		c2 := c
		c2.DeviceID, c2.Name = "0A1B2C3D-0000-4000-8000-00000000000C", "Listed twice"
		replace(t, s, tenant, MDMIntune, t0.Add(15*time.Minute), b, c, c2)
		got = byID(t, s, tenant, MDMIntune)
		c2.DeviceID = c.DeviceID
		if len(got) != 2 || !same(got[b.DeviceID], b) || !same(got[c.DeviceID], c2) || !got[c.DeviceID].LastCheckIn.IsZero() {
			t.Fatalf("second copy = %+v", got)
		}
		if st := status(t, s, tenant, MDMIntune); !at(st.LastSuccessAt, t0.Add(15*time.Minute)) || st.Devices != 2 ||
			st.TenantID != tenant || st.Source != MDMIntune || st.LastErrorAt != nil {
			t.Fatalf("status = %+v", st)
		}

		// An MDM with no Macs left empties the copy.
		replace(t, s, tenant, MDMIntune, t0.Add(30*time.Minute))
		if got := byID(t, s, tenant, MDMIntune); len(got) != 0 {
			t.Fatalf("empty copy = %+v", got)
		}
		if st := status(t, s, tenant, MDMIntune); st.Devices != 0 || !at(st.LastSuccessAt, t0.Add(30*time.Minute)) {
			t.Fatalf("status after an empty sync = %+v", st)
		}
	})

	t.Run("bySerialIsTrimmedUpperCaseNewestFirst", func(t *testing.T) {
		s, tenant := setup(t)
		older := mac("00000000-0000-4000-8000-000000000001", " c02xyz ", t0.Add(-3*time.Hour))
		newer := mac("00000000-0000-4000-8000-000000000002", "C02XYZ", t0.Add(-time.Hour))
		never := mac("00000000-0000-4000-8000-000000000003", "c02Xyz", time.Time{})
		other := mac("00000000-0000-4000-8000-000000000004", "C02XYZ1", t0)
		replace(t, s, tenant, MDMIntune, t0, older, never, other, newer)
		got, err := s.MDMDevicesBySerial(ctx, tenant, MDMIntune, " C02xyz")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || !same(got[0], newer) || !same(got[1], older) || !same(got[2], never) {
			t.Fatalf("by serial = %+v", got)
		}
		if got[0].TenantID != tenant || got[0].Source != MDMIntune {
			t.Fatalf("record = %+v", got[0])
		}
		if got, err := s.MDMDevicesBySerial(ctx, tenant, MDMIntune, "C02NONE"); err != nil || len(got) != 0 {
			t.Fatalf("unknown serial = %+v, %v", got, err)
		}
	})

	t.Run("errorKeepsDevicesAndLastSuccess", func(t *testing.T) {
		s, tenant := setup(t)
		// A sync that fails before any succeeded.
		if err := s.RecordMDMSyncError(ctx, tenant, MDMIntune, "Graph HTTP 403", t0); err != nil {
			t.Fatal(err)
		}
		if st := status(t, s, tenant, MDMIntune); st.LastSuccessAt != nil || !at(st.LastErrorAt, t0) ||
			st.LastError != "Graph HTTP 403" || st.Devices != 0 {
			t.Fatalf("status after a first failure = %+v", st)
		}

		a := mac("00000000-0000-4000-8000-00000000000a", "C02AAA", t0)
		replace(t, s, tenant, MDMIntune, t0.Add(15*time.Minute), a)
		if err := s.RecordMDMSyncError(ctx, tenant, MDMIntune, "Graph HTTP 503", t0.Add(30*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if got := byID(t, s, tenant, MDMIntune); len(got) != 1 || !same(got[a.DeviceID], a) {
			t.Fatalf("copy after a failure = %+v", got)
		}
		st := status(t, s, tenant, MDMIntune)
		if !at(st.LastSuccessAt, t0.Add(15*time.Minute)) || !at(st.LastErrorAt, t0.Add(30*time.Minute)) ||
			st.LastError != "Graph HTTP 503" || st.Devices != 1 {
			t.Fatalf("status after a failure = %+v", st)
		}
		// A later success keeps the last error, which is now older than it.
		replace(t, s, tenant, MDMIntune, t0.Add(45*time.Minute), a)
		st = status(t, s, tenant, MDMIntune)
		if !at(st.LastSuccessAt, t0.Add(45*time.Minute)) || !at(st.LastErrorAt, t0.Add(30*time.Minute)) || st.LastError != "Graph HTTP 503" {
			t.Fatalf("status after recovering = %+v", st)
		}
	})

	t.Run("claimLetsOneReplicaSync", func(t *testing.T) {
		s, tenant := setup(t)
		every := 15 * time.Minute
		claim := func(now time.Time) bool {
			t.Helper()
			ok, err := s.ClaimMDMSync(ctx, tenant, MDMIntune, now, every)
			if err != nil {
				t.Fatal(err)
			}
			return ok
		}
		if !claim(t0) || claim(t0) {
			t.Fatal("two claims at the same time: want the first only")
		}
		if claim(t0.Add(every/2 - time.Second)) {
			t.Fatal("claimed again before every/2")
		}
		if !claim(t0.Add(every/2)) || claim(t0.Add(every/2)) {
			t.Fatal("after every/2: want one claim")
		}

		// Replicas claiming at once: exactly one wins.
		next := t0.Add(every)
		var wg sync.WaitGroup
		results := make(chan bool, 8)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := s.ClaimMDMSync(ctx, tenant, MDMIntune, next, every)
				if err != nil {
					t.Error(err)
				}
				results <- ok
			}()
		}
		wg.Wait()
		close(results)
		won := 0
		for ok := range results {
			if ok {
				won++
			}
		}
		if won != 1 {
			t.Fatalf("%d replicas claimed the same sync", won)
		}
		// A claim alone isn't a sync.
		if st := status(t, s, tenant, MDMIntune); st.LastSuccessAt != nil || st.LastErrorAt != nil || st.Devices != 0 {
			t.Fatalf("status after claims = %+v", st)
		}
	})

	t.Run("clearRemovesBoth", func(t *testing.T) {
		s, tenant := setup(t)
		other := "tenant-" + randomHex(t)
		a := mac("00000000-0000-4000-8000-00000000000a", "C02AAA", t0)
		replace(t, s, tenant, MDMIntune, t0, a)
		replace(t, s, other, MDMIntune, t0, a)
		if err := s.RecordMDMSyncError(ctx, tenant, MDMIntune, "boom", t0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordSilenceHeld(ctx, tenant, MDMIntune, 6, t0); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.ClaimMDMSync(ctx, tenant, MDMIntune, t0, 15*time.Minute); err != nil || !ok {
			t.Fatalf("claim = %v, %v", ok, err)
		}

		if err := s.ClearMDM(ctx, tenant, MDMIntune); err != nil {
			t.Fatal(err)
		}
		if got := byID(t, s, tenant, MDMIntune); len(got) != 0 {
			t.Fatalf("copy after clearing = %+v", got)
		}
		if st := status(t, s, tenant, MDMIntune); st != (MDMSync{}) {
			t.Fatalf("status after clearing = %+v, want the zero value", st)
		}
		// The claim went with it.
		if ok, err := s.ClaimMDMSync(ctx, tenant, MDMIntune, t0, 15*time.Minute); err != nil || !ok {
			t.Fatalf("claim after clearing = %v, %v", ok, err)
		}
		// Clearing nothing is fine, and another tenant's copy stays.
		if err := s.ClearMDM(ctx, "tenant-"+randomHex(t), MDMIntune); err != nil {
			t.Fatal(err)
		}
		if got := byID(t, s, other, MDMIntune); len(got) != 1 {
			t.Fatalf("other tenant's copy = %+v", got)
		}
		if st := status(t, s, other, MDMIntune); st.Devices != 1 {
			t.Fatalf("other tenant's status = %+v", st)
		}
	})

	t.Run("tenantsDoNotSeeEachOther", func(t *testing.T) {
		s, tenant := setup(t)
		other := "tenant-" + randomHex(t)
		const otherSource = "other-mdm"
		mine := mac("00000000-0000-4000-8000-00000000000a", "C02SAME", t0)
		theirs := mac("00000000-0000-4000-8000-00000000000b", "C02SAME", t0)
		replace(t, s, tenant, MDMIntune, t0, mine)
		replace(t, s, other, MDMIntune, t0.Add(time.Minute), theirs, mac("00000000-0000-4000-8000-00000000000c", "C02MORE", t0))
		replace(t, s, tenant, otherSource, t0.Add(2*time.Minute), theirs)

		if got := byID(t, s, tenant, MDMIntune); len(got) != 1 || !same(got[mine.DeviceID], mine) {
			t.Fatalf("mine = %+v", got)
		}
		for _, c := range []struct {
			tenant, source string
			want           MDMDevice
		}{{tenant, MDMIntune, mine}, {other, MDMIntune, theirs}, {tenant, otherSource, theirs}} {
			got, err := s.MDMDevicesBySerial(ctx, c.tenant, c.source, "C02SAME")
			if err != nil || len(got) != 1 || !same(got[0], c.want) {
				t.Fatalf("%s/%s by serial = %+v, %v", c.tenant, c.source, got, err)
			}
		}
		if st := status(t, s, tenant, MDMIntune); st.Devices != 1 || !at(st.LastSuccessAt, t0) {
			t.Fatalf("my status = %+v", st)
		}
		if st := status(t, s, other, MDMIntune); st.Devices != 2 || !at(st.LastSuccessAt, t0.Add(time.Minute)) {
			t.Fatalf("other tenant's status = %+v", st)
		}
		if st := status(t, s, "tenant-"+randomHex(t), MDMIntune); st != (MDMSync{}) {
			t.Fatalf("never synced = %+v, want the zero value", st)
		}
		// One tenant's claim doesn't hold another's sync.
		for _, tn := range []string{tenant, other} {
			if ok, err := s.ClaimMDMSync(ctx, tn, MDMIntune, t0, 15*time.Minute); err != nil || !ok {
				t.Fatalf("%s claim = %v, %v", tn, ok, err)
			}
		}
	})

	t.Run("silenceHeldIsRecorded", func(t *testing.T) {
		s, tenant := setup(t)
		a := mac("00000000-0000-4000-8000-00000000000a", "C02AAA", t0)
		replace(t, s, tenant, MDMIntune, t0, a)
		if err := s.RecordSilenceHeld(ctx, tenant, MDMIntune, 7, t0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		st := status(t, s, tenant, MDMIntune)
		if !at(st.SilenceHeldAt, t0.Add(time.Minute)) || st.SilenceHeld != 7 || st.Devices != 1 || !at(st.LastSuccessAt, t0) {
			t.Fatalf("status = %+v", st)
		}
		if err := s.RecordSilenceHeld(ctx, tenant, MDMIntune, 3, t0.Add(2*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if st := status(t, s, tenant, MDMIntune); !at(st.SilenceHeldAt, t0.Add(2*time.Minute)) || st.SilenceHeld != 3 {
			t.Fatalf("status after a second hold = %+v", st)
		}
		// A sync leaves the hold alone.
		replace(t, s, tenant, MDMIntune, t0.Add(3*time.Minute), a)
		if st := status(t, s, tenant, MDMIntune); !at(st.SilenceHeldAt, t0.Add(2*time.Minute)) || st.SilenceHeld != 3 {
			t.Fatalf("status after a sync = %+v", st)
		}
	})
}
