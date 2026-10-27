package intune_test

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

// index is where the first call starting with prefix is among the calls, or -1.
func (r setupRun) index(prefix string) int {
	for i, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// inOrder fails the test unless the calls starting with each prefix were made, in that order.
func (r setupRun) inOrder(t *testing.T, prefixes ...string) {
	t.Helper()
	last := -1
	for _, p := range prefixes {
		i := r.index(p)
		if i < 0 {
			t.Errorf("no call starting %q in %q", p, r.calls)
			return
		}
		if i < last {
			t.Errorf("%q came before an earlier step in %q", p, r.calls)
		}
		last = i
	}
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
	cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + work, "FAKE_AZ_LOG=" + log, "SETUP_RETRY_WAIT=0"}, env...)
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
	graphApp    = "00000003-0000-0000-c000-000000000000"
	graphSP     = "66666666-0000-0000-0000-000000000006"
	roleID      = "77777777-0000-0000-0000-000000000007"
	vmPrincipal = "33333333-0000-0000-0000-000000000003"
	miClientID  = "44444444-0000-0000-0000-000000000004"
	miPrincipal = "55555555-0000-0000-0000-000000000005"
	appID       = "11111111-0000-0000-0000-000000000001"
	tenantID    = "00000000-0000-0000-0000-00000000bbbb"
	roleQuery   = "ad sp show --id " + graphApp + ` --query appRoles[?value=='DeviceManagementManagedDevices.Read.All'] | [0].id -o tsv`
)

// checkGrant checks the one assignment POST: to the principal's own appRoleAssignments,
// naming Graph's service principal and the role the tenant reported.
func checkGrant(t *testing.T, r setupRun, principal string) {
	t.Helper()
	post := r.called("rest --method POST")
	if len(post) != 1 {
		t.Fatalf("assignment POSTs: %q\nall calls: %q", post, r.calls)
	}
	if !strings.Contains(post[0], "--url https://graph.microsoft.com/v1.0/servicePrincipals/"+principal+"/appRoleAssignments") {
		t.Errorf("POST to the wrong principal: %s", post[0])
	}
	for _, s := range []string{`"principalId":"` + principal + `"`, `"resourceId":"` + graphSP + `"`, `"appRoleId":"` + roleID + `"`} {
		if !strings.Contains(post[0], s) {
			t.Errorf("POST body lacks %s: %s", s, post[0])
		}
	}
}

func TestVMGrantsTheRoleToTheVMsIdentity(t *testing.T) {
	r := runSetup(t, nil, "--vm", "rg-app/vm-altiward", "--yes")
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	if r.stdout != "ALTIWARD_INTUNE_AUTH=managed-identity\n" {
		t.Errorf("stdout:\n%s", r.stdout)
	}
	// The role is read from the tenant, then the VM gets its identity, then the grant.
	r.inOrder(t, "account show", roleQuery, "vm identity assign", "rest --method POST")
	assign := r.called("vm identity assign")
	if len(assign) != 1 || !strings.Contains(assign[0], "-g rg-app -n vm-altiward") {
		t.Errorf("vm identity assign: %q", assign)
	}
	checkGrant(t, r, vmPrincipal)
	if ad := r.called("ad app"); len(ad) > 0 {
		t.Errorf("made app registration calls with --vm: %q", ad)
	}
	for _, s := range []string{"All done", "169.254.169.254", "DeviceManagementManagedDevices.Read.All"} {
		if !strings.Contains(r.stderr, s) {
			t.Errorf("stderr lacks %q:\n%s", s, r.stderr)
		}
	}
}

func TestIdentityGrantsTheRole(t *testing.T) {
	r := runSetup(t, nil, "--identity", miClientID, "--yes")
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	want := "ALTIWARD_INTUNE_AUTH=managed-identity\nALTIWARD_INTUNE_CLIENT_ID=" + miClientID + "\n"
	if r.stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", r.stdout, want)
	}
	r.inOrder(t, "account show", roleQuery, "ad sp show --id "+miClientID, "rest --method POST")
	checkGrant(t, r, miPrincipal)
	if vm := append(r.called("vm "), r.called("ad app")...); len(vm) > 0 {
		t.Errorf("made VM or app calls with --identity: %q", vm)
	}
}

func TestAppPrintsTheSettingsOnce(t *testing.T) {
	r := runSetup(t, nil, "--app", "Altiward Intune", "--yes")
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	want := "ALTIWARD_INTUNE_AUTH=secret\n" +
		"ALTIWARD_INTUNE_TENANT_ID=" + tenantID + "\n" +
		"ALTIWARD_INTUNE_CLIENT_ID=" + appID + "\n" +
		"ALTIWARD_INTUNE_CLIENT_SECRET=fake~secret.value-123\n"
	if r.stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", r.stdout, want)
	}
	if strings.Contains(r.stderr, "fake~secret") {
		t.Error("the secret went to stderr as well")
	}
	if !strings.Contains(r.stderr, "only this once") || !strings.Contains(r.stderr, "Expires") {
		t.Errorf("stderr should say the secret is shown once, and when it expires:\n%s", r.stderr)
	}
	r.inOrder(t, "ad app list", "ad app create", "ad sp create --id "+appID, "ad app permission add",
		"ad app permission admin-consent", "ad app credential reset")
	create := r.called("ad app create")
	if len(create) != 1 || !strings.Contains(create[0], "--display-name Altiward Intune") ||
		!strings.Contains(create[0], "--sign-in-audience AzureADMyOrg") {
		t.Errorf("ad app create: %q", create)
	}
	add := r.called("ad app permission add")
	if len(add) != 1 || !strings.Contains(add[0], "--id "+appID) || !strings.Contains(add[0], "--api "+graphApp) ||
		!strings.Contains(add[0], "--api-permissions "+roleID+"=Role") {
		t.Errorf("ad app permission add: %q", add)
	}
	if consent := r.called("ad app permission admin-consent"); len(consent) != 1 || !strings.Contains(consent[0], "--id "+appID) {
		t.Errorf("admin-consent: %q", consent)
	}
	if reset := r.called("ad app credential reset"); len(reset) != 1 || !strings.Contains(reset[0], "--years 1") {
		t.Errorf("credential reset: %q", reset)
	}
	if post := r.called("rest "); len(post) > 0 {
		t.Errorf("an app is consented to, not assigned to: %q", post)
	}
}

func TestAppRetriesConsentWhileTheAppReachesEntra(t *testing.T) {
	r := runSetup(t, []string{"FAKE_CONSENT_FAILS=2"}, "--app", "Altiward Intune", "--yes")
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	if n := len(r.called("ad app permission admin-consent")); n != 3 {
		t.Errorf("admin-consent tried %d times, want 3", n)
	}
	if !strings.HasSuffix(r.stdout, "ALTIWARD_INTUNE_CLIENT_SECRET=fake~secret.value-123\n") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
}

func TestAppKeepsAnExistingAppsSecret(t *testing.T) {
	r := runSetup(t, []string{"FAKE_APPS=1"}, "--app", "Altiward Intune", "--yes")
	if r.err != nil {
		t.Fatalf("setup.sh failed: %v\n%s", r.err, r.stderr)
	}
	if len(r.called("ad app create")) > 0 || len(r.called("ad app credential")) > 0 {
		t.Errorf("must not create the app again or touch its secrets: %q", r.calls)
	}
	r.inOrder(t, "ad app permission add", "ad app permission admin-consent")
	if strings.Contains(r.stdout, "CLIENT_SECRET") || !strings.Contains(r.stdout, "ALTIWARD_INTUNE_CLIENT_ID="+appID+"\n") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
	if !strings.Contains(r.stderr, "az ad app credential reset --id "+appID+" --append") {
		t.Errorf("stderr should say how to add a secret:\n%s", r.stderr)
	}
}

func TestAppStopsOnTwoAppsWithTheName(t *testing.T) {
	r := runSetup(t, []string{"FAKE_APPS=2"}, "--app", "Altiward Intune", "--yes")
	if r.err == nil || len(r.called("ad app create")) > 0 || len(r.called("ad app permission")) > 0 {
		t.Fatalf("should stop: %v %q", r.err, r.calls)
	}
	if !strings.Contains(r.stderr, "2 app registrations") {
		t.Errorf("stderr: %s", r.stderr)
	}
}

func TestAlreadyGrantedIsNotAnError(t *testing.T) {
	r := runSetup(t, []string{"FAKE_ALREADY=1"}, "--identity", miClientID, "--yes")
	if r.err != nil {
		t.Fatalf("already granted should exit 0: %v\n%s", r.err, r.stderr)
	}
	if !strings.Contains(r.stderr, "already granted") {
		t.Errorf("stderr should say it's already granted:\n%s", r.stderr)
	}
	if !strings.Contains(r.stdout, "ALTIWARD_INTUNE_CLIENT_ID="+miClientID+"\n") {
		t.Errorf("the settings still print:\n%s", r.stdout)
	}
}

func TestOtherGraphErrorsStop(t *testing.T) {
	r := runSetup(t, []string{"FAKE_GRAPH_ERROR=1"}, "--identity", miClientID, "--yes")
	if r.err == nil || r.stdout != "" {
		t.Fatalf("should fail without settings: %v %q", r.err, r.stdout)
	}
	if !strings.Contains(r.stderr, "Insufficient privileges") || !strings.Contains(r.stderr, "Privileged Role Administrator") {
		t.Errorf("stderr should show Graph's reason and say who can grant:\n%s", r.stderr)
	}
}

func TestRefusesWithoutAMode(t *testing.T) {
	r := runSetup(t, nil)
	if exitCode(r.err) != 2 {
		t.Fatalf("exit %d, want 2: %v", exitCode(r.err), r.err)
	}
	for _, s := range []string{"--vm", "--identity", "--app", "--yes"} {
		if !strings.Contains(r.stderr, s) {
			t.Errorf("usage lacks %s:\n%s", s, r.stderr)
		}
	}
	if len(r.calls) > 0 || r.stdout != "" {
		t.Errorf("did something: calls %q stdout %q", r.calls, r.stdout)
	}
}

func TestRefusesBadArguments(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		args       []string
	}{
		{"two modes", "pass one of them", []string{"--vm", "rg/vm", "--identity", miClientID, "--yes"}},
		{"vm without a group", "<resource group>/<vm name>", []string{"--vm", "vm-altiward", "--yes"}},
		{"unknown flag", "--bogus", []string{"--identity", miClientID, "--bogus"}},
		{"missing value", "--app needs a value", []string{"--app"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runSetup(t, nil, tc.args...)
			if r.err == nil || !strings.Contains(r.stderr, tc.want) {
				t.Errorf("err %v, stderr lacks %q:\n%s", r.err, tc.want, r.stderr)
			}
			if len(r.calls) > 0 || r.stdout != "" {
				t.Errorf("did something: calls %q stdout %q", r.calls, r.stdout)
			}
		})
	}
}

func TestChecksBeforeChanging(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		env, args  []string
	}{
		{"signed out", "az login", []string{"FAKE_SIGNED_OUT=1"}, []string{"--identity", miClientID, "--yes"}},
		{"permission missing", "DeviceManagementManagedDevices.Read.All", []string{"FAKE_NO_ROLE=1"}, []string{"--vm", "rg-app/vm", "--yes"}},
		{"unknown identity", "can't find a managed identity", []string{"FAKE_NO_IDENTITY=1"}, []string{"--identity", miClientID, "--yes"}},
		{"no confirmation", "--yes", nil, []string{"--vm", "rg-app/vm"}},
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
				if strings.HasPrefix(c, "vm identity assign") || strings.HasPrefix(c, "rest --method POST") ||
					strings.HasPrefix(c, "ad app create") {
					t.Errorf("changed something: %s", c)
				}
			}
			if r.stdout != "" {
				t.Errorf("stdout: %s", r.stdout)
			}
		})
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := err.(*exec.ExitError); ok {
		return e.ExitCode()
	}
	return -1
}
