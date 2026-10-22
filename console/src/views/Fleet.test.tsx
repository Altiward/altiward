import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import type { Device } from "../api";
import { ApiContext, MeContext } from "../context";
import { fakeApi, signedIn } from "../test/fixtures";
import { FleetView } from "./Fleet";

const mac: Device = {
  serial: "C02ZM1BBMD6T", hardware_uuid: "HW", os_version: "26.1.0", agent_version: "0.1.0", privileges_version: "2.5.3",
  first_seen_at: "2026-10-16T09:00:00Z", last_seen_at: new Date().toISOString(), last_health_at: new Date().toISOString(),
  admin_members: ["asmith", "itadmin"], permanent_admins: ["itadmin"], queue_depth: 0, privileges: {},
};

describe("Fleet", () => {
  it("flags a Mac with a failing integrity check", async () => {
    const tampered: Device = {
      ...mac,
      integrity: { code_signature: true, settings_managed: false },
      recent_tamper: [
        { event_id: "t1", at: new Date().toISOString(), check: "settings_managed", state: "failed", problem: "set outside MDM: PermanentAdmins" },
      ],
    };
    const api = fakeApi({ devices: vi.fn(async () => [tampered, { ...mac, serial: "C02QUIET0001", integrity: { code_signature: true } }]) });
    render(<ApiContext.Provider value={api}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findAllByText("Needs attention")).toHaveLength(1);

    await userEvent.click(screen.getByText("C02ZM1BBMD6T"));
    const group = screen.getByRole("group", { name: "Integrity" });
    // Once in the check list, once in the alert below it.
    expect(within(group).getAllByText("Settings from MDM")).toHaveLength(2);
    expect(within(group).getByText("Failing")).toBeInTheDocument();
    expect(within(group).getByText("Passing")).toBeInTheDocument();
    expect(within(group).getByText(/set outside MDM: PermanentAdmins/)).toBeInTheDocument();
  });

  it("gives each failing check the severity the SIEM gets", async () => {
    const tampered: Device = { ...mac, integrity: { code_signature: true, settings_managed: false, launch_daemon: false, new_check: false } };
    const api = fakeApi({
      devices: vi.fn(async () => [tampered]),
      about: vi.fn(async () => ({
        version: "0.1.0", oldest_supported_agent: "0.1",
        tamper_severities: { code_signature: "High", launch_daemon: "High", settings_managed: "Medium" },
      })),
    });
    render(<ApiContext.Provider value={api}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    await userEvent.click(await screen.findByText("C02ZM1BBMD6T"));
    const group = screen.getByRole("group", { name: "Integrity" });
    // A check this server doesn't know is exported as High, so it shows as High too.
    expect(within(group).getAllByText("High severity")).toHaveLength(2);
    expect(within(group).getByText("Medium severity")).toBeInTheDocument();
    expect(within(group).getAllByText(/severity/)).toHaveLength(3);
  });

  it("explains each integrity check in a help tag", async () => {
    const checked: Device = { ...mac, integrity: { settings_managed: false, code_signature: true }, persistence_unreadable: [] };
    render(<ApiContext.Provider value={fakeApi({ devices: vi.fn(async () => [checked]) })}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    await userEvent.click(await screen.findByText("C02ZM1BBMD6T"));
    const group = screen.getByRole("group", { name: "Integrity" });
    expect(within(group).getByText("Settings from MDM")).toHaveAccessibleDescription(/configuration profile/);
    expect(within(group).getByText("App signature")).toHaveAccessibleDescription(/signature/);
    expect(within(group).getByText("Persistence check")).toHaveAccessibleDescription(/SSH keys/);
  });

  it("puts a tamper alert's problem on a line of its own", async () => {
    const problem = "/Library/Application Support/Altiward/Altiward.app/Contents/MacOS/Altiward is not the hook";
    const tampered: Device = {
      ...mac,
      integrity: { privileges_hook: false },
      recent_tamper: [{ event_id: "t1", at: new Date().toISOString(), check: "privileges_hook", state: "failed", problem }],
    };
    const api = fakeApi({ devices: vi.fn(async () => [tampered]) });
    render(<ApiContext.Provider value={api}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    await userEvent.click(await screen.findByText("C02ZM1BBMD6T"));
    const alerts = screen.getByRole("list", { name: "Recent integrity alerts" });
    const item = within(alerts).getByRole("listitem");
    expect(within(item).getByText("Privileges reports to Altiward")).toBeInTheDocument();
    const detail = within(item).getByText(`Failed: ${problem}`);
    expect(detail).toHaveClass("detail");
  });

  it("opens filtered by a search or a problem from the overview's links", async () => {
    const failing: Device = { ...mac, integrity: { code_signature: false } };
    const quiet: Device = { ...mac, serial: "C02QUIET0001", integrity: { code_signature: true } };
    const old: Device = { ...mac, serial: "C02OLD000001", agent_version: "0.0.4" };
    const api = fakeApi({ devices: vi.fn(async () => [failing, quiet, old]) });
    const { unmount } = render(
      <ApiContext.Provider value={api}><MemoryRouter initialEntries={["/fleet?show=attention"]}><FleetView /></MemoryRouter></ApiContext.Provider>,
    );
    expect(await screen.findByText("C02ZM1BBMD6T")).toBeInTheDocument();
    expect(screen.queryByText("C02QUIET0001")).toBeNull();
    expect(screen.getByText(/Showing Macs failing an integrity check/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show all Macs" }));
    expect(await screen.findByText("C02QUIET0001")).toBeInTheDocument();
    unmount();

    render(<ApiContext.Provider value={api}><MemoryRouter initialEntries={["/fleet?show=outdated"]}><FleetView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findByText("C02OLD000001")).toBeInTheDocument();
    expect(screen.queryByText("C02ZM1BBMD6T")).toBeNull();
  });

  it("starts with the search the link gave", async () => {
    const api = fakeApi({ devices: vi.fn(async () => [mac, { ...mac, serial: "C02QUIET0001" }]) });
    render(<ApiContext.Provider value={api}><MemoryRouter initialEntries={["/fleet?q=QUIET"]}><FleetView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findByText("C02QUIET0001")).toBeInTheDocument();
    expect(screen.queryByText("C02ZM1BBMD6T")).toBeNull();
    expect(screen.getByRole("searchbox")).toHaveValue("QUIET");
  });

  it("shows where the persistence check can't read", async () => {
    const blind: Device = { ...mac, integrity: { code_signature: true }, persistence_unreadable: ["/Users/jdoe/.ssh/authorized_keys"] };
    const clear: Device = { ...mac, serial: "C02CLEAR0001", integrity: { code_signature: true }, persistence_unreadable: [] };
    const api = fakeApi({ devices: vi.fn(async () => [blind, clear]) });
    render(<ApiContext.Provider value={api}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findAllByText("Partly checked")).toHaveLength(1);
    expect(screen.queryByText("Needs attention")).toBeNull();

    await userEvent.click(screen.getByText("C02ZM1BBMD6T"));
    let group = screen.getByRole("group", { name: "Integrity" });
    expect(within(group).getByText("Can’t read 1 place")).toBeInTheDocument();
    expect(within(group).getByText("/Users/jdoe/.ssh/authorized_keys")).toBeInTheDocument();

    await userEvent.click(screen.getByText("C02CLEAR0001"));
    group = screen.getByRole("group", { name: "Integrity" });
    expect(within(group).getByText("Reads every place")).toBeInTheDocument();
  });

  it("times check-ins by when the server heard from the Mac, not the Mac's clock", async () => {
    const behind: Device = {
      ...mac, last_seen_at: "2026-10-01T09:00:00Z", last_health_at: "2026-10-01T09:00:00Z",
      last_received_at: new Date().toISOString(),
    };
    const api = fakeApi({ devices: vi.fn(async () => [behind]) });
    render(<ApiContext.Provider value={api}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findByText("Just now")).toBeInTheDocument();
    expect(screen.queryByText("Late")).toBeNull();
  });

  it("offers revokes only to roles that may revoke", async () => {
    for (const [role, offered] of [["viewer", false], ["operator", true]] as const) {
      const api = fakeApi({ devices: vi.fn(async () => [mac]) });
      const { unmount } = render(
        <ApiContext.Provider value={api}><MeContext.Provider value={signedIn(role)}>
          <MemoryRouter><FleetView /></MemoryRouter>
        </MeContext.Provider></ApiContext.Provider>);
      await userEvent.click(await screen.findByText("C02ZM1BBMD6T"));
      const inspector = screen.getByRole("complementary", { name: "Mac details" });
      expect(within(inspector).queryByRole("button", { name: "Revoke all admin rights…" }) !== null).toBe(offered);
      expect(within(inspector).queryByRole("button", { name: "Revoke asmith…" }) !== null).toBe(offered);
      expect(within(inspector).queryByText(/needs the operator role/) !== null).toBe(!offered);
      unmount();
    }
  });

  it("tags a Mac the server reported silent until it resumes", async () => {
    const quiet: Device = {
      ...mac, last_seen_at: "2026-10-12T09:00:00Z", last_health_at: "2026-10-12T09:00:00Z",
      silence: { event_id: "q1", at: "2026-10-15T09:00:00Z", state: "silent", last_seen_at: "2026-10-12T09:00:00Z" },
    };
    const back: Device = { ...mac, serial: "C02BACK00001",
      silence: { event_id: "q2", at: new Date().toISOString(), state: "resumed", last_seen_at: new Date().toISOString() } };
    const api = fakeApi({ devices: vi.fn(async () => [quiet, back]) });
    render(<ApiContext.Provider value={api}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findAllByText("Not checking in")).toHaveLength(1);

    await userEvent.click(screen.getByText("C02ZM1BBMD6T"));
    const inspector = screen.getByRole("complementary", { name: "Mac details" });
    expect(within(inspector).getByText(/Alert raised .* ago/)).toBeInTheDocument();
  });

  it("tags Macs whose agent is older than the server supports", async () => {
    const api = fakeApi({
      devices: vi.fn(async () => [{ ...mac, agent_version: "0.0.4" }, { ...mac, serial: "C02CURRENT01" }]),
      about: vi.fn(async () => ({ version: "0.1.0", oldest_supported_agent: "0.1" })),
    });
    render(<ApiContext.Provider value={api}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findAllByText("Agent outdated")).toHaveLength(1);
  });

  it("lists the permanent admins from the Mac's profile, read-only", async () => {
    const api = fakeApi({ devices: vi.fn(async () => [{ ...mac, permanent_admins: ["itadmin", "breakglass"] }]) });
    render(<ApiContext.Provider value={api}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    await userEvent.click(await screen.findByText("C02ZM1BBMD6T"));
    const group = screen.getByRole("group", { name: "Permanent admins" });
    expect(within(group).getByText("itadmin").nextSibling).toHaveTextContent("Admin now");
    expect(within(group).getByText("breakglass").nextSibling).toHaveTextContent("Not an admin now");
    expect(within(group).getByText(/configuration profile/)).toBeInTheDocument();
    expect(within(group).queryByRole("button")).toBeNull();
  });

  it("leaves out permanent admins an agent didn't report", async () => {
    const api = fakeApi({ devices: vi.fn(async () => [{ ...mac, permanent_admins: undefined }]) });
    render(<ApiContext.Provider value={api}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    await userEvent.click(await screen.findByText("C02ZM1BBMD6T"));
    expect(screen.queryByRole("group", { name: "Permanent admins" })).toBeNull();
  });

  it("offers revoke for elevated users but not permanent admins", async () => {
    const pending = { command_id: "c1", serial: "C02ZM1BBMD6T", user: "asmith", status: "pending", result: null };
    const api = fakeApi({
      devices: vi.fn(async () => [mac]),
      revokeDevice: vi.fn(async () => pending as never),
      command: vi.fn(async () => ({
        ...pending, status: "completed",
        result: { status: "completed", error: null, revoked: ["asmith"], failed: [], skipped: [], completed_at: "2026-10-16T09:20:00Z" },
      }) as never),
    });
    render(<ApiContext.Provider value={api}><MemoryRouter><FleetView /></MemoryRouter></ApiContext.Provider>);
    await userEvent.click(await screen.findByText("C02ZM1BBMD6T"));
    const group = screen.getByRole("group", { name: "Admin group" });
    expect(within(group).getByRole("button", { name: "Revoke asmith…" })).toBeInTheDocument();
    expect(within(group).queryByRole("button", { name: "Revoke itadmin…" })).toBeNull();
    expect(within(group).getByText("Permanent")).toBeInTheDocument();

    await userEvent.click(within(group).getByRole("button", { name: "Revoke asmith…" }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Revoke" }));
    expect(api.revokeDevice).toHaveBeenCalledWith("C02ZM1BBMD6T", "asmith");
    expect(await screen.findByText("Admin rights removed from asmith on C02ZM1BBMD6T.")).toBeInTheDocument();
  });
});
