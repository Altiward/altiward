package splunk_test

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"
)

// The parts of a Simple XML dashboard the test checks.
type dashboard struct {
	XMLName xml.Name `xml:"form"`
	Inputs  []struct {
		Token string `xml:"token,attr"`
	} `xml:"fieldset>input"`
	Searches []search `xml:"search"`
	Panels   []struct {
		Title string `xml:"title"`
		Viz   []struct {
			Searches []search `xml:"search"`
		} `xml:",any"` // the table, single or chart
	} `xml:"row>panel"`
}

type search struct {
	ID    string `xml:"id,attr"`
	Base  string `xml:"base,attr"`
	Query string `xml:"query"`
}

func TestDashboardSearchesReadAltiwardEvents(t *testing.T) {
	b, err := os.ReadFile("altiward_overview.xml")
	if err != nil {
		t.Fatal(err)
	}
	var d dashboard
	if err := xml.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	tokens := map[string]bool{}
	for _, in := range d.Inputs {
		tokens[in.Token] = true
	}
	if !tokens["index"] || !tokens["period"] {
		t.Fatalf("inputs = %v, want index and period", tokens)
	}
	bases := map[string]bool{}
	all := d.Searches
	for _, s := range d.Searches {
		bases[s.ID] = true
	}
	panels := 0
	for _, p := range d.Panels {
		if len(p.Viz) != 1 || len(p.Viz[0].Searches) != 1 {
			t.Errorf("panel %q needs one visualization with one search", p.Title)
			continue
		}
		panels++
		all = append(all, p.Viz[0].Searches...)
	}
	for _, s := range all {
		switch {
		case s.Base != "":
			if !bases[s.Base] {
				t.Errorf("search on unknown base %q", s.Base)
			}
		case !strings.Contains(s.Query, `index="$index$" sourcetype="altiward:ocsf"`):
			t.Errorf("search doesn't read Altiward's events from the chosen index: %.60q", s.Query)
		}
	}
	if panels < 10 {
		t.Fatalf("only %d panels", panels)
	}
}
