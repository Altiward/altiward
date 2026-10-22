package sentinel_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// setupRun is one run of setup.sh against testdata/fake-az.sh.
type setupRun struct {
	err            error
	stdout, stderr string
	calls          []string // az's arguments, one call each
}

func (r setupRun) called(prefix string) []string {
	var out []string
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// runSetup runs setup.sh with bash, in an empty directory, with only the fake az and the
// system's tools on PATH. env sets the fake's FAKE_* state.
func runSetup(t *testing.T, env []string, args ...string) setupRun {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	script, err := filepath.Abs("setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	fake, err := os.ReadFile("testdata/fake-az.sh")
	if err != nil {
		t.Fatal(err)
	}
	bin, work := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "az"), fake, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(bin, "calls.log")
	cmd := exec.Command(bash, append([]string{script}, args...)...)
	cmd.Dir = work
	cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + work, "FAKE_AZ_LOG=" + log}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	r := setupRun{err: cmd.Run(), stdout: stdout.String(), stderr: stderr.String()}
	if b, err := os.ReadFile(log); err == nil {
		r.calls = strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	}
	if left, _ := os.ReadDir(work); len(left) > 0 {
		t.Errorf("setup.sh left files in the working directory: %v", left)
	}
	if strings.Contains(r.stderr, "unexpected call") {
		t.Errorf("setup.sh made a call the fake az doesn't know:\n%s", r.stderr)
	}
	return r
}

const (
	ruleID    = "/subscriptions/00000000-0000-0000-0000-00000000aaaa/resourceGroups/rg-sec/providers/Microsoft.Insights/dataCollectionRules/dcr-altiward"
	dceID     = "/subscriptions/00000000-0000-0000-0000-00000000aaaa/resourceGroups/rg-sec/providers/Microsoft.Insights/dataCollectionEndpoints/dce-altiward"
	directURL = "https://dcr-altiward-wxyz.westeurope-1.ingest.monitor.azure.com"
	dceURL    = "https://dce-altiward-abcd.westeurope-1.ingest.monitor.azure.com"
)

func TestSetupFreshPrintsTheFiveEnvLines(t *testing.T) {
	r := runSetup(t, nil, "--resource-group", "rg-sec", "--workspace", "law-sec")
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	want := "ALTIWARD_SENTINEL_ENDPOINT=" + directURL + "\n" +
		"ALTIWARD_SENTINEL_DCR_ID=dcr-0123456789abcdef0123456789abcdef\n" +
		"ALTIWARD_SENTINEL_TENANT_ID=00000000-0000-0000-0000-00000000bbbb\n" +
		"ALTIWARD_SENTINEL_CLIENT_ID=11111111-0000-0000-0000-000000000001\n" +
		"ALTIWARD_SENTINEL_CLIENT_SECRET=fake~secret.value-123\n"
	if r.stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", r.stdout, want)
	}
	if strings.Contains(r.stderr, "fake~secret") {
		t.Error("the secret went to stderr as well")
	}
	if !strings.Contains(r.stderr, "westeurope") || !strings.Contains(r.stderr, "Expires") {
		t.Errorf("stderr should name the region and the secret's expiry:\n%s", r.stderr)
	}

	create := r.called("monitor log-analytics workspace table create")
	if len(create) != 1 || !strings.Contains(create[0], "-n AltiwardOCSF_CL") ||
		!strings.Contains(create[0], "TimeGenerated=datetime EventUid=string TenantUid=string SessionUid=string ClassUid=int ActivityId=int SeverityId=int DeviceSerial=string UserName=string Message=string Ocsf=dynamic") {
		t.Errorf("table create: %q", create)
	}
	put := r.called("rest --method put --url " + ruleID + "?api-version=2023-03-11")
	if len(put) != 1 {
		t.Fatalf("rule PUTs: %q\nall calls: %q", put, r.calls)
	}
	for _, s := range []string{`"kind":"Direct"`, `"location":"westeurope"`, `"Custom-AltiwardOCSF"`,
		`"outputStream":"Custom-AltiwardOCSF_CL"`, `"transformKql":"source"`, `{"name":"Ocsf","type":"dynamic"}`,
		`"workspaceResourceId":"/subscriptions/00000000-0000-0000-0000-00000000aaaa/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/law-sec"`} {
		if !strings.Contains(put[0], s) {
			t.Errorf("rule body lacks %s: %s", s, put[0])
		}
	}
	if strings.Contains(put[0], "dataCollectionEndpointId") || len(r.called("rest --method put --url "+dceID)) > 0 {
		t.Error("a rule without --private-link shouldn't use an endpoint")
	}
	rbac := r.called("ad sp create-for-rbac")
	if len(rbac) != 1 || !strings.Contains(rbac[0], `--scopes `+ruleID) ||
		!strings.Contains(rbac[0], "--role Monitoring Metrics Publisher") || !strings.Contains(rbac[0], "-n Altiward SIEM export") {
		t.Errorf("create-for-rbac: %q", rbac)
	}
}

func TestSetupKeepsAnExistingAppsSecret(t *testing.T) {
	r := runSetup(t, []string{"FAKE_TABLE=ok", "FAKE_APPS=1"}, "-g", "rg-sec", "-w", "law-sec")
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	if len(r.called("ad sp create-for-rbac")) > 0 || len(r.called("ad app credential")) > 0 {
		t.Errorf("must not touch an existing app's secrets: %q", r.calls)
	}
	if len(r.called("monitor log-analytics workspace table create")) > 0 {
		t.Error("created a table that exists")
	}
	if strings.Contains(r.stdout, "CLIENT_SECRET") || !strings.Contains(r.stdout, "ALTIWARD_SENTINEL_CLIENT_ID=11111111-0000-0000-0000-000000000001\n") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
	if !strings.Contains(r.stderr, "az ad app credential reset --id 11111111-0000-0000-0000-000000000001 --append") ||
		!strings.Contains(r.stderr, "Rotate the secret") {
		t.Errorf("stderr should say how to add a secret:\n%s", r.stderr)
	}
	// The app gets the role on the rule if it lacks it, as after a switch to --private-link.
	grant := r.called("role assignment create")
	if len(grant) != 1 || !strings.Contains(grant[0], "--scope "+ruleID) || !strings.Contains(grant[0], "--assignee-object-id 22222222-0000-0000-0000-000000000002") {
		t.Errorf("role assignment create: %q", grant)
	}

	r = runSetup(t, []string{"FAKE_TABLE=ok", "FAKE_APPS=1", "FAKE_ROLE=1"}, "-g", "rg-sec", "-w", "law-sec")
	if r.err != nil || len(r.called("role assignment create")) > 0 {
		t.Errorf("granted a role the app has: %v %q", r.err, r.calls)
	}
}

func TestSetupStopsOnTwoAppsWithTheName(t *testing.T) {
	r := runSetup(t, []string{"FAKE_APPS=2"}, "-g", "rg-sec", "-w", "law-sec")
	if r.err == nil || len(r.called("ad sp create-for-rbac")) > 0 || len(r.called("role assignment create")) > 0 {
		t.Fatalf("should stop: %v %q", r.err, r.calls)
	}
	if !strings.Contains(r.stderr, "--app-name") {
		t.Errorf("stderr: %s", r.stderr)
	}
}

func TestSetupStopsOnATableWithOtherColumns(t *testing.T) {
	r := runSetup(t, []string{"FAKE_TABLE=wrong"}, "-g", "rg-sec", "-w", "law-sec")
	if r.err == nil {
		t.Fatal("should fail")
	}
	if !strings.Contains(r.stderr, "Ocsf") || !strings.Contains(r.stderr, "dynamic") {
		t.Errorf("stderr should name the column: %s", r.stderr)
	}
	if len(r.called("rest --method put")) > 0 || len(r.called("ad ")) > 0 || len(r.called("monitor log-analytics workspace table create")) > 0 {
		t.Errorf("went on after the table check: %q", r.calls)
	}
}

func TestSetupPrivateLinkUsesAnEndpoint(t *testing.T) {
	r := runSetup(t, nil, "-g", "rg-sec", "-w", "law-sec", "--private-link")
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	dce := r.called("rest --method put --url " + dceID + "?api-version=2023-03-11")
	if len(dce) != 1 || !strings.Contains(dce[0], `"location":"westeurope"`) {
		t.Fatalf("endpoint PUT: %q", dce)
	}
	rule := r.called("rest --method put --url " + ruleID)
	if len(rule) != 1 || !strings.Contains(rule[0], `"dataCollectionEndpointId":"`+dceID+`"`) {
		t.Errorf("rule should name the endpoint: %q", rule)
	}
	if !strings.HasPrefix(r.stdout, "ALTIWARD_SENTINEL_ENDPOINT="+dceURL+"\n") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
	if !strings.Contains(r.stderr, "private link scope") {
		t.Errorf("stderr should say to add the endpoint to the scope:\n%s", r.stderr)
	}

	// An endpoint that exists is kept as it is.
	r = runSetup(t, []string{"FAKE_DCE=exists", "FAKE_TABLE=ok"}, "-g", "rg-sec", "-w", "law-sec", "--private-link")
	if r.err != nil || len(r.called("rest --method put --url "+dceID)) > 0 {
		t.Errorf("replaced an existing endpoint: %v %q", r.err, r.calls)
	}
}

func TestSetupStopsWhenTheRuleHasNoIngestionURL(t *testing.T) {
	r := runSetup(t, []string{"FAKE_NO_DIRECT_URL=1"}, "-g", "rg-sec", "-w", "law-sec")
	if r.err == nil || len(r.called("ad sp create-for-rbac")) > 0 {
		t.Fatalf("should stop before the app: %v %q", r.err, r.calls)
	}
	if !strings.Contains(r.stderr, "no ingestion URL") {
		t.Errorf("stderr: %s", r.stderr)
	}
}

func TestSetupChecksBeforeChanging(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		env, args  []string
	}{
		{"signed out", "az login", []string{"FAKE_SIGNED_OUT=1"}, []string{"-g", "rg-sec", "-w", "law-sec"}},
		{"no workspace", "law-other", nil, []string{"-g", "rg-sec", "-w", "law-other"}},
		{"provider", "az provider register", []string{"FAKE_PROVIDER=NotRegistered"}, []string{"-g", "rg-sec", "-w", "law-sec"}},
		{"no arguments", "--resource-group", nil, nil},
		{"unknown flag", "--bogus", nil, []string{"-g", "rg-sec", "-w", "law-sec", "--bogus"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runSetup(t, tc.env, tc.args...)
			if r.err == nil {
				t.Fatal("should fail")
			}
			if !strings.Contains(r.stderr, tc.want) {
				t.Errorf("stderr lacks %q:\n%s", tc.want, r.stderr)
			}
			for _, c := range r.calls {
				if strings.Contains(c, "create") || strings.Contains(c, "--method put") {
					t.Errorf("changed something: %s", c)
				}
			}
			if r.stdout != "" {
				t.Errorf("stdout: %s", r.stdout)
			}
		})
	}
}

func TestSetupWithVMUsesItsManagedIdentityAndNoApp(t *testing.T) {
	r := runSetup(t, nil, "--resource-group", "rg-sec", "--workspace", "law-sec",
		"--vm", "vm-altiward", "--vm-resource-group", "rg-app")
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	want := "ALTIWARD_SENTINEL_ENDPOINT=" + directURL + "\n" +
		"ALTIWARD_SENTINEL_DCR_ID=dcr-0123456789abcdef0123456789abcdef\n" +
		"ALTIWARD_SENTINEL_AUTH=managed-identity\n"
	if r.stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", r.stdout, want)
	}
	if ad := r.called("ad "); len(ad) > 0 {
		t.Errorf("made app registration calls with --vm: %q", ad)
	}
	assign := r.called("vm identity assign")
	if len(assign) != 1 || !strings.Contains(assign[0], "-g rg-app -n vm-altiward") {
		t.Errorf("vm identity assign: %q", assign)
	}
	role := r.called("role assignment create")
	if len(role) != 1 || !strings.Contains(role[0], "--assignee-object-id 33333333-0000-0000-0000-000000000003") ||
		!strings.Contains(role[0], "--scope "+ruleID) || !strings.Contains(role[0], "--role Monitoring Metrics Publisher") {
		t.Errorf("role assignment: %q", role)
	}
}

func TestSetupWithVMKeepsAnExistingRole(t *testing.T) {
	r := runSetup(t, []string{"FAKE_ROLE=1"}, "--resource-group", "rg-sec", "--workspace", "law-sec", "--vm", "vm-altiward")
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	if assign := r.called("vm identity assign"); len(assign) != 1 || !strings.Contains(assign[0], "-g rg-sec -n vm-altiward") {
		t.Errorf("the VM's group should default to the workspace's: %q", assign)
	}
	if role := r.called("role assignment create"); len(role) != 0 {
		t.Errorf("assigned a role the identity has: %q", role)
	}
}

func TestSetupRefusesAVMGroupWithoutAVM(t *testing.T) {
	r := runSetup(t, nil, "--resource-group", "rg-sec", "--workspace", "law-sec", "--vm-resource-group", "rg-app")
	if r.err == nil || !strings.Contains(r.stderr, "--vm") || len(r.calls) > 0 {
		t.Errorf("err %v, calls %q, stderr:\n%s", r.err, r.calls, r.stderr)
	}
}

func TestSetupWithIdentityUsesItAndNoApp(t *testing.T) {
	const clientID = "44444444-0000-0000-0000-000000000004"
	r := runSetup(t, nil, "--resource-group", "rg-sec", "--workspace", "law-sec", "--identity", clientID)
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	want := "ALTIWARD_SENTINEL_ENDPOINT=" + directURL + "\n" +
		"ALTIWARD_SENTINEL_DCR_ID=dcr-0123456789abcdef0123456789abcdef\n" +
		"ALTIWARD_SENTINEL_AUTH=managed-identity\n" +
		"ALTIWARD_SENTINEL_CLIENT_ID=" + clientID + "\n"
	if r.stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", r.stdout, want)
	}
	if apps := append(r.called("ad app"), r.called("ad sp create-for-rbac")...); len(apps) > 0 {
		t.Errorf("made app registration calls with --identity: %q", apps)
	}
	if vm := r.called("vm "); len(vm) > 0 {
		t.Errorf("made VM calls with --identity: %q", vm)
	}
	role := r.called("role assignment create")
	if len(role) != 1 || !strings.Contains(role[0], "--assignee-object-id 55555555-0000-0000-0000-000000000005") ||
		!strings.Contains(role[0], "--scope "+ruleID) || !strings.Contains(role[0], "--role Monitoring Metrics Publisher") {
		t.Errorf("role assignment: %q", role)
	}
	if !strings.Contains(r.stderr, "az containerapp update") {
		t.Errorf("doesn't say how to set it on a container app:\n%s", r.stderr)
	}
}

func TestSetupStopsOnAnUnknownIdentity(t *testing.T) {
	r := runSetup(t, []string{"FAKE_NO_IDENTITY=1"}, "--resource-group", "rg-sec", "--workspace", "law-sec",
		"--identity", "44444444-0000-0000-0000-000000000004")
	if r.err == nil || !strings.Contains(r.stderr, "can't find a managed identity") || r.stdout != "" {
		t.Errorf("err %v, stdout %q, stderr:\n%s", r.err, r.stdout, r.stderr)
	}
	if role := r.called("role assignment create"); len(role) != 0 {
		t.Errorf("assigned a role: %q", role)
	}
}

func TestSetupRefusesAVMAndAnIdentity(t *testing.T) {
	r := runSetup(t, nil, "--resource-group", "rg-sec", "--workspace", "law-sec", "--vm", "vm-altiward",
		"--identity", "44444444-0000-0000-0000-000000000004")
	if r.err == nil || !strings.Contains(r.stderr, "pass one of them") || len(r.calls) > 0 {
		t.Errorf("err %v, calls %q, stderr:\n%s", r.err, r.calls, r.stderr)
	}
}
