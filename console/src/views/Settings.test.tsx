import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { ApiContext, MeContext } from "../context";
import { fakeApi, githubFetch, release, signedIn } from "../test/fixtures";
import { checkReleases, showsPrereleases } from "../updates";
import type { ConsoleSignIn, HistoryPolicy } from "../api";
import { dateOnly, dateTime } from "../format";
import { setLook } from "../theme";
import { SettingsView } from "./Settings";

/** Settings at one of its tabs' addresses, as the app routes it. */
function settingsAt(path: string) {
  return <MemoryRouter initialEntries={[path]}><Routes><Route path="/settings/*" element={<SettingsView />} /></Routes></MemoryRouter>;
}

function renderView(api: ReturnType<typeof fakeApi>, path = "/settings") {
  render(<ApiContext.Provider value={api}>{settingsAt(path)}</ApiContext.Provider>);
}

describe("Settings tabs", () => {
  it("shows every tab to an admin, each at its own address, the current one marked", async () => {
    renderView(fakeApi(), "/settings/siem");
    const tabs = screen.getByRole("navigation", { name: "Settings sections" });
    const links = within(tabs).getAllByRole("link");
    expect(links.map((l) => [l.textContent, l.getAttribute("href")])).toEqual([
      ["General", "/settings"], ["SIEM export", "/settings/siem"], ["Sign-ins", "/settings/sign-ins"],
      ["Updates", "/settings/updates"],
    ]);
    expect(within(tabs).getByRole("link", { name: "SIEM export" })).toHaveAttribute("aria-current", "page");
    expect(within(tabs).getByRole("link", { name: "General" })).not.toHaveAttribute("aria-current");
    expect(await screen.findByRole("heading", { name: "SIEM export" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Enrollment" })).not.toBeInTheDocument();
  });

  it("shows operators and viewers General and SIEM export only, and sends them back from the others", async () => {
    render(<ApiContext.Provider value={fakeApi()}><MeContext.Provider value={signedIn("viewer")}>
      {settingsAt("/settings/updates")}
    </MeContext.Provider></ApiContext.Provider>);
    const tabs = screen.getByRole("navigation", { name: "Settings sections" });
    expect(within(tabs).getAllByRole("link").map((l) => l.textContent)).toEqual(["General", "SIEM export"]);
    expect(await screen.findByRole("heading", { name: "Enrollment" })).toBeInTheDocument();
    expect(within(tabs).getByRole("link", { name: "General" })).toHaveAttribute("aria-current", "page");
  });

  it("opens General for an address it doesn't know", async () => {
    renderView(fakeApi(), "/settings/nowhere");
    expect(await screen.findByRole("heading", { name: "Enrollment" })).toBeInTheDocument();
  });
});

describe("Settings", () => {
  it("explains the secure approval default and preserves an explicit opt-out", async () => {
    const api = fakeApi({
      settings: vi.fn(async () => ({ reenrollment_requires_approval: true, silent_after_hours: 48, silent_alerts_off: false })),
      putSettings: vi.fn(async (s) => s),
    });
    renderView(api);
    const approval = await screen.findByRole("switch", { name: /Approve Macs that enrol again/ });
    await waitFor(() => expect(approval).toBeEnabled());
    expect(approval).toBeChecked();
    expect(screen.getByText(/Turning this off lets anyone with the enrolment token/)).toBeInTheDocument();
    expect(screen.getByText(/by naming its serial and hardware UUID\./)).toBeInTheDocument();
    await userEvent.click(approval);
    expect(api.putSettings).toHaveBeenCalledWith({
      reenrollment_requires_approval: false, silent_after_hours: 48, silent_alerts_off: false,
    });
  });

  it("leaves approving every new Mac off until an admin turns it on", async () => {
    const api = fakeApi({
      settings: vi.fn(async () => ({
        reenrollment_requires_approval: true, new_mac_requires_approval: false, silent_after_hours: 0, silent_alerts_off: false,
      })),
      putSettings: vi.fn(async (s) => s),
    });
    renderView(api);
    const newMacs = await screen.findByRole("switch", { name: /Approve every new Mac/ });
    await waitFor(() => expect(newMacs).toBeEnabled());
    expect(newMacs).not.toBeChecked();
    expect(screen.getByText(/A Mac's first key waits for approval in Enrollments/)).toBeInTheDocument();
    await userEvent.click(newMacs);
    expect(api.putSettings).toHaveBeenCalledWith({
      reenrollment_requires_approval: true, new_mac_requires_approval: true, silent_after_hours: 0, silent_alerts_off: false,
    });
  });

  it("shows the default silence limit and saves a new one without touching the rest", async () => {
    const api = fakeApi({
      settings: vi.fn(async () => ({ reenrollment_requires_approval: true, silent_after_hours: 0, silent_alerts_off: false })),
      putSettings: vi.fn(async (s) => s),
    });
    renderView(api);
    // The field renders empty until the settings load.
    const field = await screen.findByDisplayValue("72");
    expect(field).toHaveRole("spinbutton");
    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();

    await userEvent.clear(field);
    await userEvent.type(field, "24");
    await userEvent.click(save);
    expect(api.putSettings).toHaveBeenCalledWith({
      reenrollment_requires_approval: true, silent_after_hours: 24, silent_alerts_off: false,
    });
  });

  it("changes the theme and light or dark for this browser, whatever the role", async () => {
    render(<ApiContext.Provider value={fakeApi()}><MeContext.Provider value={signedIn("viewer")}>
      {settingsAt("/settings")}
    </MeContext.Provider></ApiContext.Provider>);
    const theme = screen.getByRole("group", { name: "Theme" });
    expect(within(theme).getByRole("button", { name: "Mono" })).toHaveAttribute("aria-pressed", "true");

    await userEvent.click(within(theme).getByRole("button", { name: "Moss" }));
    await userEvent.click(within(screen.getByRole("group", { name: "Light or dark" })).getByRole("button", { name: "Dark" }));
    expect(within(theme).getByRole("button", { name: "Moss" })).toHaveAttribute("aria-pressed", "true");
    expect(document.documentElement.dataset).toMatchObject({ theme: "moss", appearance: "dark" });
    expect(JSON.parse(localStorage.getItem("altiward.look")!)).toEqual({ theme: "moss", appearance: "dark" });
    setLook({ theme: "mono", appearance: "system" });
  });

  it("lets only admins change settings", async () => {
    const api = fakeApi();
    render(<ApiContext.Provider value={api}><MeContext.Provider value={signedIn("operator")}>
      {settingsAt("/settings")}
    </MeContext.Provider></ApiContext.Provider>);
    expect(await screen.findByDisplayValue("72")).toBeDisabled();
    for (const s of screen.getAllByRole("switch")) expect(s).toBeDisabled();
    expect(screen.getByText(/Changing settings needs the admin role/)).toBeInTheDocument();
  });

  it("refuses hours out of range", async () => {
    const api = fakeApi({ putSettings: vi.fn(async (s) => s) });
    renderView(api);
    const field = await screen.findByDisplayValue("72");
    await userEvent.clear(field);
    await userEvent.type(field, "1000");
    expect(screen.getByRole("alert")).toHaveTextContent("from 1 to 720");
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("keeps the silence limit when the enrollment switch changes", async () => {
    const api = fakeApi({
      settings: vi.fn(async () => ({ reenrollment_requires_approval: false, silent_after_hours: 48, silent_alerts_off: false })),
      putSettings: vi.fn(async (s) => s),
    });
    renderView(api);
    await userEvent.click(await screen.findByRole("switch", { name: /Approve Macs that enrol again/ }));
    expect(api.putSettings).toHaveBeenCalledWith({
      reenrollment_requires_approval: true, silent_after_hours: 48, silent_alerts_off: false,
    });
  });

  it("turns silence alerts off and keeps the limit", async () => {
    const api = fakeApi({
      settings: vi.fn(async () => ({ reenrollment_requires_approval: false, silent_after_hours: 48, silent_alerts_off: false })),
      putSettings: vi.fn(async (s) => s),
    });
    renderView(api);
    const alerts = await screen.findByRole("switch", { name: /Alert when a Mac stops checking in/ });
    expect(alerts).toBeChecked();
    await userEvent.click(alerts);
    expect(api.putSettings).toHaveBeenCalledWith({
      reenrollment_requires_approval: false, silent_after_hours: 48, silent_alerts_off: true,
    });
  });

  it("disables the hours when silence alerts are off", async () => {
    const api = fakeApi({
      settings: vi.fn(async () => ({ reenrollment_requires_approval: false, silent_after_hours: 0, silent_alerts_off: true })),
    });
    renderView(api);
    expect(await screen.findByDisplayValue("72")).toBeDisabled();
    expect(screen.getByRole("switch", { name: /Alert when a Mac stops checking in/ })).not.toBeChecked();
  });

  describe("keep history for", () => {
    const policy = (over: Partial<HistoryPolicy>): HistoryPolicy => ({
      days: 365, kept_for_good: false, reason: "default_siem", held_before: null, waiting_for_backfill: false, ...over,
    });
    const history = (over: Partial<HistoryPolicy> = {}, stored = 0, sinks = true) => fakeApi({
      settings: vi.fn(async () => ({ reenrollment_requires_approval: true, silent_after_hours: 48, silent_alerts_off: false, history_days: stored })),
      retention: vi.fn(async () => ({ history: policy(over) })),
      exports: vi.fn(async () => (sinks ? [{ sink: "splunk", pending: 0, failing: 0, oldest_queued_at: null, max_attempts: 8, last_delivered_at: null }] : [])),
      putSettings: vi.fn(async (s) => s),
    });
    const choose = (to: string) => userEvent.selectOptions(screen.getByRole("combobox", { name: "Keep history for" }), to);
    const saveHistory = () => screen.getByRole("button", { name: "Save history period" });

    it.each([
      [{}, "1 year, the default with a SIEM connected"],
      [{ days: 0, reason: "default_no_siem" as const }, "Kept for good: no SIEM is connected"],
      [{ days: 120, reason: "set" as const }, "120 days"],
      [{ days: 0, kept_for_good: true, reason: "kept_for_good" as const }, "Kept for good"],
    ])("says the period in force for %j", async (over, sentence) => {
      renderView(history(over));
      expect(await screen.findByText(sentence)).toBeInTheDocument();
    });

    it("says when history is held back for the SIEM, and when nothing is removed yet", async () => {
      renderView(history({ held_before: "2026-10-01T00:00:00Z", waiting_for_backfill: true }));
      expect(await screen.findByText(
        `History from before ${dateOnly("2026-10-01T00:00:00Z")}, when your SIEM was connected, is kept until you replay it to the SIEM.`,
      )).toBeInTheDocument();
      expect(screen.getByText("Nothing is removed until the admin group has been sent to your SIEM.")).toBeInTheDocument();
    });

    it("asks before shortening the period, and saves it only once confirmed", async () => {
      const api = history();
      renderView(api);
      await screen.findByText("1 year, the default with a SIEM connected");
      await choose("Days");
      const field = screen.getByLabelText("Days of history");
      await userEvent.clear(field);
      await userEvent.type(field, "120");
      await userEvent.click(saveHistory());
      const sheet = screen.getByRole("dialog");
      expect(within(sheet).getByRole("heading", { name: "Remove older history?" })).toBeInTheDocument();
      expect(sheet).toHaveTextContent("History older than 120 days will be removed at the next daily run. Your SIEM keeps what it was sent.");
      expect(api.putSettings).not.toHaveBeenCalled();
      await userEvent.click(within(sheet).getByRole("button", { name: "Remove" }));
      expect(api.putSettings).toHaveBeenCalledWith({
        reenrollment_requires_approval: true, silent_after_hours: 48, silent_alerts_off: false, history_days: 120,
      });
      await waitFor(() => expect(api.retention).toHaveBeenCalledTimes(2));
    });

    it("saves nothing when the sheet is cancelled", async () => {
      const api = history();
      renderView(api);
      await screen.findByText("1 year, the default with a SIEM connected");
      await choose("Days");
      const field = screen.getByLabelText("Days of history");
      await userEvent.clear(field);
      await userEvent.type(field, "120");
      await userEvent.click(saveHistory());
      await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.putSettings).not.toHaveBeenCalled();
    });

    it("saves a longer period without asking", async () => {
      const api = history();
      renderView(api);
      await screen.findByText("1 year, the default with a SIEM connected");
      await choose("Days");
      const field = screen.getByLabelText("Days of history");
      await userEvent.clear(field);
      await userEvent.type(field, "1000");
      await userEvent.click(saveHistory());
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.putSettings).toHaveBeenCalledWith(expect.objectContaining({ history_days: 1000 }));
    });

    it("keeps for good without asking", async () => {
      const api = history();
      renderView(api);
      await screen.findByText("1 year, the default with a SIEM connected");
      await choose("Keep for good");
      await userEvent.click(saveHistory());
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.putSettings).toHaveBeenCalledWith(expect.objectContaining({ history_days: -1 }));
    });

    it("asks when going from kept for good to the default with a SIEM connected", async () => {
      const api = history({ days: 0, kept_for_good: true, reason: "kept_for_good" }, -1);
      renderView(api);
      await screen.findByText("Kept for good");
      await choose("Default");
      await userEvent.click(saveHistory());
      expect(screen.getByRole("dialog")).toHaveTextContent("History older than 365 days will be removed");
      expect(api.putSettings).not.toHaveBeenCalled();
    });

    it("saves the default without asking when no SIEM is connected", async () => {
      const api = history({ days: 0, kept_for_good: true, reason: "kept_for_good" }, -1, false);
      renderView(api);
      await screen.findByText("Kept for good");
      await choose("Default");
      await userEvent.click(saveHistory());
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.putSettings).toHaveBeenCalledWith(expect.objectContaining({ history_days: 0 }));
    });

    it("can't save fewer than 90 days or more than 3650", async () => {
      const api = history();
      renderView(api);
      await screen.findByText("1 year, the default with a SIEM connected");
      await choose("Days");
      const field = screen.getByLabelText("Days of history");
      await userEvent.clear(field);
      await userEvent.type(field, "89");
      expect(screen.getByRole("alert")).toHaveTextContent("from 90 to 3650");
      expect(saveHistory()).toBeDisabled();
      await userEvent.clear(field);
      await userEvent.type(field, "3651");
      expect(saveHistory()).toBeDisabled();
      expect(api.putSettings).not.toHaveBeenCalled();
    });

    it("shows a viewer the choice, disabled", async () => {
      render(<ApiContext.Provider value={history()}><MeContext.Provider value={signedIn("viewer")}>
        {settingsAt("/settings")}
      </MeContext.Provider></ApiContext.Provider>);
      expect(await screen.findByText("1 year, the default with a SIEM connected")).toBeInTheDocument();
      expect(screen.getByRole("combobox", { name: "Keep history for" })).toBeDisabled();
      expect(saveHistory()).toBeDisabled();
    });
  });

  describe("console sign-ins", () => {
    const signIn = (over: Partial<ConsoleSignIn>): ConsoleSignIn => ({
      id: "a".repeat(64), actor: "bob@example.com", name: "Bob", role: "viewer", current: false,
      created_at: "2026-10-17T21:00:00Z", ends_at: "2026-10-18T09:00:00Z", expires_at: "2026-10-17T23:00:00Z", ...over,
    });

    it("lists who is signed in and lets an admin end someone else's sign-in", async () => {
      const api = fakeApi({
        consoleSessions: vi.fn(async () => [
          signIn({ id: "b".repeat(64), actor: "jane.doe@example.com", name: "Jane Doe", role: "admin", current: true }),
          signIn({}),
        ]),
        endConsoleSession: vi.fn(async () => undefined),
      });
      renderView(api, "/settings/sign-ins");
      const bob = await screen.findByRole("group", { name: "Bob" });
      expect(bob).toHaveTextContent("bob@example.com · viewer");
      const jane = screen.getByRole("group", { name: "Jane Doe (you)" });
      expect(jane.querySelector("button")).toBeNull();

      await userEvent.click(screen.getByRole("button", { name: "End sign-in" }));
      expect(api.endConsoleSession).toHaveBeenCalledWith("a".repeat(64));
      expect(await screen.findByRole("status")).toHaveTextContent("Bob is signed out");
      expect(api.consoleSessions).toHaveBeenCalledTimes(2);
    });

    it("isn't shown to operators and viewers", async () => {
      const api = fakeApi({ consoleSessions: vi.fn(async () => [signIn({})]) });
      render(<ApiContext.Provider value={api}><MeContext.Provider value={signedIn("operator")}>
        {settingsAt("/settings/sign-ins")}
      </MeContext.Provider></ApiContext.Provider>);
      await screen.findByDisplayValue("72");
      expect(screen.queryByText("Signed in to the console")).not.toBeInTheDocument();
      expect(api.consoleSessions).not.toHaveBeenCalled();
    });
  });

  describe("SIEM export", () => {
    const failing = {
      sink: "sentinel", pending: 3, failing: 3, oldest_queued_at: "2026-10-17T09:00:00Z", max_attempts: 4,
      last_error: "sentinel: HTTP 403: forbidden", last_delivered_at: null,
    };
    const upToDate = {
      sink: "splunk", pending: 0, failing: 0, oldest_queued_at: null, max_attempts: 0,
      last_delivered_at: "2026-10-17T22:30:00Z",
    };

    it("shows each SIEM's state in words and retries a failing one now", async () => {
      const api = fakeApi({
        exports: vi.fn(async () => [failing, upToDate]),
        retryExports: vi.fn(async () => ({ retried: 3 })),
      });
      renderView(api, "/settings/siem");
      const sentinel = await screen.findByRole("group", { name: "Microsoft Sentinel" });
      expect(sentinel).toHaveTextContent("Failing");
      expect(sentinel).toHaveTextContent("3 waiting");
      expect(sentinel).toHaveTextContent("sentinel: HTTP 403: forbidden");
      expect(sentinel).toHaveTextContent("Nothing delivered yet.");
      const splunk = screen.getByRole("group", { name: "Splunk" });
      expect(splunk).toHaveTextContent("Up to date");
      expect(splunk).toHaveTextContent(`Last delivered ${dateTime("2026-10-17T22:30:00Z")}.`);
      expect(screen.getAllByRole("button", { name: "Retry now" })).toHaveLength(1);

      await userEvent.click(screen.getByRole("button", { name: "Retry now" }));
      expect(api.retryExports).toHaveBeenCalledWith("sentinel");
      expect(api.exports).toHaveBeenCalledTimes(2);
    });

    it("sends a test event to every SIEM", async () => {
      const api = fakeApi({
        exports: vi.fn(async () => [upToDate]),
        testExport: vi.fn(async () => ({ queued_for: ["splunk"] })),
      });
      renderView(api, "/settings/siem");
      await userEvent.click(await screen.findByRole("button", { name: "Send test event" }));
      expect(api.testExport).toHaveBeenCalled();
      expect(await screen.findByRole("status")).toHaveTextContent("Test event queued for Splunk");
    });

    it("says how to connect a SIEM when there is none", async () => {
      renderView(fakeApi({ exports: vi.fn(async () => []) }), "/settings/siem");
      expect(await screen.findByText(/No SIEM is connected/)).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Send test event" })).not.toBeInTheDocument();
      expect(screen.getByRole("heading", { name: "Connect a SIEM" })).toBeInTheDocument();
      expect(screen.getByText(/go in the server’s .env/)).toBeInTheDocument();
      const splunk = screen.getByText("Splunk", { selector: "summary" }).closest("details")!;
      expect(splunk).toHaveTextContent("ALTIWARD_SPLUNK_HEC_TOKEN=<the HEC token>");
      expect(splunk).toHaveTextContent("# Optional. The index to write to. Unset, the token’s default index.");
      expect(splunk).toHaveTextContent("# ALTIWARD_SPLUNK_INDEX=<an index>");
      // The guide for the server that's running.
      await waitFor(() => expect(within(splunk).getByRole("link", { name: "Splunk setup guide" }))
        .toHaveAttribute("href", "https://github.com/Altiward/altiward/blob/server-v0.1.0/integrations/splunk/README.md#setup"));
      expect(within(splunk).getByRole("button", { name: "Copy" })).toBeInTheDocument();
      expect(screen.getByText("Microsoft Sentinel", { selector: "summary" })).toBeInTheDocument();
    });

    it("offers only the SIEMs that aren't connected", async () => {
      renderView(fakeApi({ exports: vi.fn(async () => [failing, upToDate]) }), "/settings/siem");
      expect(await screen.findByRole("heading", { name: "Connect another SIEM" })).toBeInTheDocument();
      const offered = [...document.querySelectorAll(".siem-guide summary")].map((s) => s.textContent);
      expect(offered).toHaveLength(1);
      expect(offered[0]).not.toMatch(/Splunk|Sentinel/);
    });

    it("on Azure Container Apps, gives the commands for the app, and Sentinel's managed identity", async () => {
      renderView(fakeApi({
        exports: vi.fn(async () => []),
        about: vi.fn(async () => ({
          version: "0.7.0", oldest_supported_agent: "0.4", update_check: false,
          platform: "azure-container-apps" as const, app: "altiward-app",
        })),
      }), "/settings/siem");
      expect(await screen.findByText(/environment variables on the container app/)).toBeInTheDocument();
      const sentinel = screen.getByText("Microsoft Sentinel", { selector: "summary" }).closest("details")!;
      expect(sentinel).toHaveTextContent("az containerapp update --name altiward-app");
      expect(sentinel).toHaveTextContent("ALTIWARD_SENTINEL_AUTH=managed-identity");
      expect(sentinel).not.toHaveTextContent("CLIENT_SECRET");
      const splunk = screen.getByText("Splunk", { selector: "summary" }).closest("details")!;
      expect(splunk).toHaveTextContent("ALTIWARD_SPLUNK_HEC_TOKEN=secretref:splunk-hec-token");
      expect(within(splunk).getByRole("list", { name: "Optional Splunk settings" }))
        .toHaveTextContent("ALTIWARD_SPLUNK_INDEX. The index to write to.");
    });

    it("lets only admins test or retry", async () => {
      const api = fakeApi({ exports: vi.fn(async () => [failing]) });
      render(<ApiContext.Provider value={api}><MeContext.Provider value={signedIn("viewer")}>
        {settingsAt("/settings/siem")}
      </MeContext.Provider></ApiContext.Provider>);
      expect(await screen.findByRole("button", { name: "Retry now" })).toBeDisabled();
      expect(screen.getByRole("button", { name: "Send test event" })).toBeDisabled();
    });
  });
});

describe("Settings SIEM queue", () => {
  it("shows what is waiting as sending", async () => {
    const api = fakeApi({ exports: vi.fn(async () => [{ sink: "splunk", pending: 4, failing: 0, max_attempts: 0, oldest_queued_at: null, last_delivered_at: null }]) });
    renderView(api, "/settings/siem");
    const row = await screen.findByRole("group", { name: "Splunk" });
    expect(row).toHaveTextContent("4 waiting to be sent.");
    expect(row).toHaveTextContent("Sending");
  });
});

describe("Settings updates", () => {
  const withCheck = (version = "0.1.0") => fakeApi({
    about: vi.fn(async () => ({ version, oldest_supported_agent: "0.1", update_check: true })),
    devices: vi.fn(async () => [{ agent_version: "0.1.2" }, { agent_version: "0.1.0" }] as never),
  });

  it("shows the latest versions, when they were checked, and how to upgrade", async () => {
    githubFetch();
    renderView(withCheck(), "/settings/updates");
    const group = await screen.findByRole("group", { name: "Updates" });
    const server = await within(group).findByRole("group", { name: "Server" });
    expect(within(server).getByText("You’re running 0.1.0. The latest release is 0.2.0.")).toBeInTheDocument();
    expect(within(server).getByText("Update available")).toBeInTheDocument();
    const agent = within(group).getByRole("group", { name: "Agent" });
    await within(agent).findByText("The newest agent in your fleet is 0.1.2. The latest release is 0.2.0.");
    expect(within(agent).getByText("Update available")).toBeInTheDocument();
    expect(within(group).getByText(/^Last checked /)).toBeInTheDocument();
    expect(within(group).getByText("./upgrade.sh 0.2.0")).toBeInTheDocument();
  });

  it("on Azure Container Apps, says which image to change to and where the setting lives", async () => {
    githubFetch();
    renderView(fakeApi({
      about: vi.fn(async () => ({ version: "0.1.0", oldest_supported_agent: "0.1", update_check: true,
        platform: "azure-container-apps" as const, app: "altiwardlab" })),
    }), "/settings/updates");
    const group = await screen.findByRole("group", { name: "Updates" });
    expect(await within(group).findByText("ghcr.io/altiward/altiward-api:0.2.0")).toBeInTheDocument();
    expect(within(group).queryByText(/upgrade\.sh/)).toBeNull();
    expect(within(group).getByText(/in the container app’s environment variables turns it off/)).toBeInTheDocument();
  });

  it("says when the server is up to date", async () => {
    githubFetch();
    renderView(withCheck("0.2.0"), "/settings/updates");
    const server = await screen.findByRole("group", { name: "Server" });
    expect(within(server).getByText("Up to date")).toBeInTheDocument();
  });

  it("says a server newer than the latest release is newer, not up to date", async () => {
    githubFetch();
    renderView(withCheck("0.2.1"), "/settings/updates");
    const server = await screen.findByRole("group", { name: "Server" });
    expect(within(server).getByText("You’re running 0.2.1, newer than the latest release, 0.2.0.")).toBeInTheDocument();
    expect(within(server).queryByText("Up to date")).toBeNull();
  });

  it("shows release candidates once an admin turns on Show pre-releases", async () => {
    githubFetch();
    renderView(withCheck("0.2.0"), "/settings/updates");
    const group = await screen.findByRole("group", { name: "Updates" });
    const server = await within(group).findByRole("group", { name: "Server" });
    expect(within(server).getByText("You’re running 0.2.0. The latest release is 0.2.0.")).toBeInTheDocument();
    const toggle = within(group).getByRole("switch", { name: /Show pre-releases/ });
    expect(toggle).not.toBeChecked();

    await userEvent.click(toggle);
    expect(showsPrereleases()).toBe(true);
    expect(within(server).getByText("You’re running 0.2.0. The latest release is 0.2.0. The newest release candidate is 0.3.0-rc.1."))
      .toBeInTheDocument();
    expect(within(server).getByText("Update available")).toBeInTheDocument();
    const notice = within(group).getByRole("region", { name: "Server release candidate 0.3.0-rc.1 is available" });
    expect(within(notice).getByText("./upgrade.sh 0.3.0-rc.1")).toBeInTheDocument();
  });

  it("names the release and the candidate for a server running one", async () => {
    githubFetch();
    renderView(withCheck("0.3.0-rc.1"), "/settings/updates");
    const server = await screen.findByRole("group", { name: "Server" });
    expect(within(server).getByText("You’re running 0.3.0-rc.1. The latest release is 0.2.0. The newest release candidate is 0.3.0-rc.1."))
      .toBeInTheDocument();
    expect(within(server).getByText("Up to date")).toBeInTheDocument();
  });

  it("says it couldn’t check, and when it last could", async () => {
    githubFetch();
    const before = await checkReleases(Date.now() - 2 * 24 * 60 * 60 * 1000);
    githubFetch("offline");
    renderView(withCheck(), "/settings/updates");
    const group = await screen.findByRole("group", { name: "Updates" });
    expect(await within(group).findByText("Couldn’t check for updates")).toBeInTheDocument();
    expect(within(group).getByText(`Last checked ${dateTime(before.checkedAt!)}.`)).toBeInTheDocument();
    expect(within(group).queryByText("Update available")).toBeNull();
  });

  it("checks again when an admin presses Check now", async () => {
    githubFetch([release("server-v0.1.0"), release("agent-v0.1.2")]);
    await checkReleases(Date.now() - 2 * 60_000);
    const fetch = githubFetch();
    renderView(withCheck(), "/settings/updates");
    const server = await screen.findByRole("group", { name: "Server" });
    expect(within(server).getByText("Up to date")).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Check now" }));
    expect(await within(await screen.findByRole("group", { name: "Server" })).findByText("Update available")).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("offers Check now after a failed check", async () => {
    githubFetch("offline");
    await checkReleases(Date.now() - 2 * 60_000);
    renderView(withCheck(), "/settings/updates");
    const group = await screen.findByRole("group", { name: "Updates" });
    await within(group).findByText("Couldn’t check for updates");
    githubFetch();
    await userEvent.click(within(group).getByRole("button", { name: "Check now" }));
    expect(await within(group).findByText("You’re running 0.1.0. The latest release is 0.2.0.")).toBeInTheDocument();
  });

  it("says the check is off when the server turned it off", async () => {
    const fetch = githubFetch();
    const api = fakeApi();
    renderView(api, "/settings/updates");
    const group = await screen.findByRole("group", { name: "Updates" });
    expect(await within(group).findByText(/ALTIWARD_UPDATE_CHECK=false/)).toBeInTheDocument();
    expect(within(group).getByText(/is set in the server’s \.env/)).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("says the check is off in the container app’s settings on Azure Container Apps", async () => {
    renderView(fakeApi({
      about: vi.fn(async () => ({ version: "0.1.0", oldest_supported_agent: "0.1", update_check: false,
        platform: "azure-container-apps" as const, app: "altiwardlab" })),
    }), "/settings/updates");
    const group = await screen.findByRole("group", { name: "Updates" });
    expect(await within(group).findByText(/is set in the container app’s environment variables/)).toBeInTheDocument();
  });

  it("isn't shown to an operator", async () => {
    const fetch = githubFetch();
    const api = withCheck();
    render(<ApiContext.Provider value={api}><MeContext.Provider value={signedIn("operator")}>
      {settingsAt("/settings/updates")}
    </MeContext.Provider></ApiContext.Provider>);
    await screen.findByDisplayValue("72");
    await waitFor(() => expect(api.settings).toHaveBeenCalled());
    expect(screen.queryByRole("group", { name: "Updates" })).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});
