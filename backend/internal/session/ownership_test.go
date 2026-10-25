package session_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Altiward/altiward/backend/internal/event"
	"github.com/Altiward/altiward/backend/internal/session"
	"github.com/Altiward/altiward/backend/internal/testfixture"
)

func TestConflictingOwnerCannotChangeReducerState(t *testing.T) {
	for _, field := range []string{"serial", "hardware", "account", "session"} {
		t.Run(field, func(t *testing.T) {
			grant := testfixture.Event(t, "elevation-granted")
			s := session.New("tenant", *grant.SessionID)
			if err := s.Apply(grant); err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(s)
			conflict := testfixture.Event(t, "elevation-revoked")
			conflict.Detail = map[string]any{"verified": false, "orphan": true, "inferred": true}
			switch field {
			case "serial":
				conflict.Device.Serial = "OTHER-MAC"
			case "hardware":
				conflict.Device.HardwareUUID = "OTHER-HARDWARE"
			case "account":
				conflict.User = &event.User{LocalName: "other"}
			case "session":
				id := "00000000-0000-4000-8000-000000000001"
				conflict.SessionID = &id
			}
			if err := s.Apply(conflict); !errors.Is(err, session.ErrOwnerConflict) {
				t.Fatalf("error %v", err)
			}
			after, _ := json.Marshal(s)
			if !bytes.Equal(before, after) {
				t.Fatalf("conflicting event changed state: %s", after)
			}
		})
	}
}

func TestUnknownLegacyOwnershipIsFilledWithoutChangingKnownFields(t *testing.T) {
	grant := testfixture.Event(t, "elevation-granted")
	s := session.New("tenant", *grant.SessionID)
	s.DeviceSerial = grant.Device.Serial
	activity := grant
	activity.Type, activity.User, activity.Elevation = event.Activity, nil, nil
	if err := s.Apply(activity); err != nil {
		t.Fatal(err)
	}
	if s.LocalUser != "" || s.HardwareUUID != grant.Device.HardwareUUID {
		t.Fatalf("unexpected owner %+v", s)
	}
	if err := s.Apply(grant); err != nil {
		t.Fatal(err)
	}
	if s.LocalUser != grant.User.LocalName {
		t.Fatalf("account not bound: %+v", s)
	}
	if err := s.Apply(activity); err != nil {
		t.Fatal(err)
	}
	if s.LocalUser != grant.User.LocalName {
		t.Fatal("accountless event cleared known owner")
	}
}
