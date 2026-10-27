package mdm_test

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// readValue reads the next plist value: <dict>, <array>, <string>, <integer>, <true/> or
// <false/>. Comments and whitespace are skipped. Integers come back as "integer:N" so
// they never equal a string with the same digits.
func readValue(d *xml.Decoder) (any, error) {
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			return readStarted(d, se)
		}
	}
}

// readStarted reads the value whose start element has already been taken.
func readStarted(d *xml.Decoder, se xml.StartElement) (any, error) {
	switch se.Name.Local {
	case "string", "integer":
		var s string
		if err := d.DecodeElement(&s, &se); err != nil {
			return nil, err
		}
		if se.Name.Local == "integer" {
			return "integer:" + strings.TrimSpace(s), nil
		}
		return s, nil
	case "true":
		return true, d.Skip()
	case "false":
		return false, d.Skip()
	case "dict":
		m := map[string]any{}
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return m, nil
			case xml.StartElement:
				if t.Name.Local != "key" {
					return nil, fmt.Errorf("a dict holds <%s> where a key goes", t.Name.Local)
				}
				var key string
				if err := d.DecodeElement(&key, &t); err != nil {
					return nil, err
				}
				v, err := readValue(d)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
		}
	case "array":
		var a []any
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return a, nil
			case xml.StartElement:
				v, err := readStarted(d, t)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
		}
	}
	return nil, fmt.Errorf("unexpected <%s>", se.Name.Local)
}

// readPlist returns a plist file's top-level dict.
func readPlist(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	d.Entity = xml.HTMLEntity
	for {
		tok, err := d.Token()
		if err == io.EOF {
			t.Fatalf("%s has no <plist>", path)
		}
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "plist" {
			break
		}
	}
	v, err := readValue(d)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s: the top level isn't a dict", path)
	}
	return m
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestMobileconfigsMatchTheirPlists keeps each ready-made profile in step with the plist
// whose settings it carries: the same keys with the same values, so a change to one that
// forgets the other fails here.
func TestMobileconfigsMatchTheirPlists(t *testing.T) {
	for _, tc := range []struct {
		domain, identifier string
	}{
		{"com.altiward.agent", "com.altiward.profile.agent"},
		{"corp.sap.privileges", "com.altiward.profile.privileges"},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			plist := readPlist(t, tc.domain+".plist")
			profile := readPlist(t, tc.domain+".mobileconfig")

			if profile["PayloadType"] != "Configuration" {
				t.Errorf("PayloadType = %v, want Configuration", profile["PayloadType"])
			}
			if profile["PayloadIdentifier"] != tc.identifier {
				t.Errorf("PayloadIdentifier = %v, want %s", profile["PayloadIdentifier"], tc.identifier)
			}
			if s, _ := profile["PayloadUUID"].(string); len(s) != 36 {
				t.Errorf("PayloadUUID = %q, want a fixed UUID", s)
			}
			content, _ := profile["PayloadContent"].([]any)
			if len(content) != 1 {
				t.Fatalf("PayloadContent holds %d payloads, want 1", len(content))
			}
			payload, _ := content[0].(map[string]any)
			if payload["PayloadType"] != tc.domain {
				t.Errorf("payload PayloadType = %v, want the preference domain %s", payload["PayloadType"], tc.domain)
			}
			if payload["PayloadIdentifier"] != tc.identifier+".settings" {
				t.Errorf("payload PayloadIdentifier = %v, want %s.settings", payload["PayloadIdentifier"], tc.identifier)
			}
			if s, _ := payload["PayloadUUID"].(string); len(s) != 36 || s == profile["PayloadUUID"] {
				t.Errorf("payload PayloadUUID = %q, want a UUID of its own", s)
			}

			settings := map[string]any{}
			for k, v := range payload {
				if !strings.HasPrefix(k, "Payload") {
					settings[k] = v
				}
			}
			if !reflect.DeepEqual(keys(settings), keys(plist)) {
				t.Fatalf("keys differ:\n profile %v\n plist   %v", keys(settings), keys(plist))
			}
			for k, want := range plist {
				if !reflect.DeepEqual(settings[k], want) {
					t.Errorf("%s: profile has %#v, plist has %#v", k, settings[k], want)
				}
			}
		})
	}
}
