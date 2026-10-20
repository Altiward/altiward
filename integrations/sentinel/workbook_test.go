package sentinel_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"strings"
	"testing"
)

// go test ./integrations/sentinel -run Workbook -update rewrites workbook.arm.json from
// workbook.json, after editing the workbook.
var update = flag.Bool("update", false, "rewrite workbook.arm.json from workbook.json")

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

func TestWorkbookQueriesReadTheAltiwardTable(t *testing.T) {
	wb := readJSON(t, "workbook.json")
	if wb["version"] != "Notebook/1.0" {
		t.Fatalf("version = %v", wb["version"])
	}
	queries := 0
	for _, raw := range wb["items"].([]any) {
		item := raw.(map[string]any)
		if item["type"] != 3.0 {
			continue
		}
		queries++
		c := item["content"].(map[string]any)
		name := item["name"]
		if q, _ := c["query"].(string); !strings.Contains(q, "AltiwardOCSF_CL") {
			t.Errorf("%s doesn't read AltiwardOCSF_CL", name)
		}
		if c["resourceType"] != "microsoft.operationalinsights/workspaces" {
			t.Errorf("%s: resourceType %v", name, c["resourceType"])
		}
		// Each query follows the period picker, or looks back far enough to say what's true now.
		if c["timeContextFromParameter"] != "TimeRange" && c["timeContext"] == nil {
			t.Errorf("%s has no time range", name)
		}
	}
	if queries < 8 {
		t.Fatalf("only %d queries", queries)
	}
}

// armTemplate is the ARM template that installs the workbook in a workspace's resource
// group. Its name comes from the workspace, so deploying it again updates the workbook.
func armTemplate(workbook map[string]any) map[string]any {
	return map[string]any{
		"$schema":        "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		"contentVersion": "1.0.0.0",
		"parameters": map[string]any{
			"workspaceName": map[string]any{"type": "string", "metadata": map[string]any{
				"description": "The Log Analytics workspace Altiward sends events to (the one with the AltiwardOCSF_CL table).",
			}},
			"workbookName": map[string]any{"type": "string", "defaultValue": "Altiward overview"},
			"location":     map[string]any{"type": "string", "defaultValue": "[resourceGroup().location]"},
		},
		"variables": map[string]any{
			"workspaceId":     "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]",
			"workbookContent": workbook,
		},
		"resources": []any{map[string]any{
			"type":       "Microsoft.Insights/workbooks",
			"apiVersion": "2022-04-01",
			"name":       "[guid(variables('workspaceId'), 'altiward-overview')]",
			"location":   "[parameters('location')]",
			"kind":       "shared",
			"properties": map[string]any{
				"displayName":    "[parameters('workbookName')]",
				"category":       "sentinel",
				"sourceId":       "[variables('workspaceId')]",
				"serializedData": "[string(variables('workbookContent'))]",
				"version":        "Notebook/1.0",
			},
		}},
	}
}

func TestWorkbookTemplateEmbedsTheWorkbook(t *testing.T) {
	wb := readJSON(t, "workbook.json")
	want := armTemplate(wb)
	if *update {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(want); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("workbook.arm.json", buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Round-trip, so both sides are plain decoded JSON.
	b, _ := json.Marshal(want)
	var wantJSON map[string]any
	_ = json.Unmarshal(b, &wantJSON)
	if got := readJSON(t, "workbook.arm.json"); !reflect.DeepEqual(got, wantJSON) {
		t.Fatal("workbook.arm.json is out of date: run go test ./integrations/sentinel -run Workbook -update")
	}
}

// ARM evaluates a string that starts with "[" as an expression, so none in the workbook may.
func TestWorkbookHasNoStringARMWouldEvaluate(t *testing.T) {
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch v := v.(type) {
		case string:
			if strings.HasPrefix(v, "[") {
				t.Errorf("%s starts with [: %.40q", path, v)
			}
		case map[string]any:
			for k, x := range v {
				walk(path+"."+k, x)
			}
		case []any:
			for _, x := range v {
				walk(path+"[]", x)
			}
		}
	}
	walk("workbook", readJSON(t, "workbook.json"))
}
