package store

import (
	"fmt"
	"testing"
)

// TestHoldsForApproval covers every Intune outcome against both approval settings, with the
// strict setting on and off, and the hardware UUID rule. A match never makes a key active
// that today's rules hold.
func TestHoldsForApproval(t *testing.T) {
	checks := []MDMCheck{MDMNotChecked, MDMNotSent, MDMInvalidID, MDMMatch, MDMMismatch, MDMUnknownID, MDMUnavailable}
	active := &DeviceCredential{HardwareUUID: "HW-1"}
	for _, strict := range []bool{false, true} {
		for _, approval := range []bool{false, true} {
			for _, enrolledBefore := range []bool{false, true} {
				for _, check := range checks {
					settings := TenantSettings{
						ReenrollmentRequiresApproval: approval, NewMacRequiresApproval: approval, RequireIntuneMatch: strict,
					}
					// Today's rules, without Intune.
					today := approval
					want := today
					switch {
					case check == MDMMismatch:
						want = true
					case strict && check != MDMMatch && check != MDMNotChecked:
						want = true
					}
					name := fmt.Sprintf("strict=%v approval=%v before=%v check=%q", strict, approval, enrolledBefore, check)
					var prev *DeviceCredential
					if enrolledBefore {
						prev = active
					}
					if got := holdsForApproval(settings, enrolledBefore, prev, "HW-1", check); got != want {
						t.Errorf("%s, same hardware: holds = %v, want %v", name, got, want)
					}
					if check == MDMMatch && today && !holdsForApproval(settings, enrolledBefore, prev, "HW-1", check) {
						t.Errorf("%s: a match made a held key active", name)
					}
					// Another hardware UUID than the active key's always holds, whatever Intune says.
					if !holdsForApproval(settings, true, active, "HW-2", check) {
						t.Errorf("%s, other hardware: not held", name)
					}
				}
			}
		}
	}
}
