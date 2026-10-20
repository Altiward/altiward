package sentinel_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/integrations/sentinel"
)

// TestColumnsDescribeRow keeps Columns, which setup.sh declares, in step with the Row type.
func TestColumnsDescribeRow(t *testing.T) {
	kind := func(f reflect.StructField) string {
		switch {
		case f.Type == reflect.TypeOf(time.Time{}):
			return "datetime"
		case f.Type.Kind() == reflect.String:
			return "string"
		case f.Type.Kind() == reflect.Int:
			return "int"
		case f.Type.Kind() == reflect.Interface:
			return "dynamic"
		}
		return "unknown " + f.Type.String()
	}
	var got []string
	rt := reflect.TypeOf(sentinel.Row{})
	for i := range rt.NumField() {
		f := rt.Field(i)
		got = append(got, strings.Split(f.Tag.Get("json"), ",")[0]+":"+kind(f))
	}
	if strings.Join(got, " ") != strings.Join(strings.Fields(sentinel.Columns), " ") {
		t.Fatalf("Row is\n  %v\nColumns is\n  %v", got, strings.Fields(sentinel.Columns))
	}
}
