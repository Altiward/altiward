import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import type { AuditEntry } from "../api";
import { ApiContext } from "../context";
import { fakeApi } from "../test/fixtures";
import { ActivityView, actorLabel, auditSummary } from "./Activity";

const entry = (over: Partial<AuditEntry>): AuditEntry => ({
  id: "a1", tenant_id: "acme", at: "2026-10-17T09:00:00Z", actor: "token:3f2a9c1b", action: "revoke_device",
  target: "C02XK0AAJGH5", detail: {}, seq: 1, ...over,
});

describe("Activity", () => {
  it("lists console actions with who did them", async () => {
    const api = fakeApi({ audit: vi.fn(async () => [
      entry({ id: "a2", detail: { serial: "C02XK0AAJGH5", user: "jdoe" } }),
      entry({ id: "a1", action: "change_settings", target: "settings", at: "2026-10-16T09:00:00Z",
        detail: { previous: { reenrollment_requires_approval: false, silent_after_hours: 0 },
          settings: { reenrollment_requires_approval: false, silent_after_hours: 24 } } }),
    ]) });
    render(<ApiContext.Provider value={api}><MemoryRouter><ActivityView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findByText("Revoked admin rights on a Mac")).toBeInTheDocument();
    expect(screen.getByText("jdoe on C02XK0AAJGH5")).toBeInTheDocument();
    expect(screen.getByText("Alert after hours without a check-in: default → 24")).toBeInTheDocument();
    expect(screen.getAllByText("Console token 3f2a9c1b")).toHaveLength(2);
  });

  it("names the silence alert switch the way the console shows it", () => {
    const off = entry({ action: "change_settings", target: "settings",
      detail: { previous: { silent_after_hours: 0 }, settings: { silent_after_hours: 0, silent_alerts_off: true } } });
    expect(auditSummary(off)).toBe("Alert when a Mac stops checking in: on → off");
    // An entry from before the switch existed, changing something else, doesn't list it.
    const hours = entry({ action: "change_settings", target: "settings",
      detail: { previous: { silent_after_hours: 0 }, settings: { silent_after_hours: 24, silent_alerts_off: false } } });
    expect(auditSummary(hours)).toBe("Alert after hours without a check-in: default → 24");
  });

  it("names the switch for approving every new Mac", () => {
    const on = entry({ action: "change_settings", target: "settings",
      detail: { previous: { new_mac_requires_approval: false }, settings: { new_mac_requires_approval: true } } });
    expect(auditSummary(on)).toBe("Approve every new Mac: off → on");
  });

  it("names an ended console sign-in", () => {
    const ended = entry({ action: "end_console_session", target: "jane@example.com", detail: { name: "Jane Doe" } });
    expect(auditSummary(ended)).toBe("Jane Doe (jane@example.com)");
  });

  it("says when a whole Mac was revoked", () => {
    expect(auditSummary(entry({ detail: { serial: "C02XK0AAJGH5", user: null } })))
      .toBe("Everyone but permanent admins on C02XK0AAJGH5");
  });

  it("names people, tokens and break-glass tokens", () => {
    expect(actorLabel("jane.doe@example.com")).toBe("jane.doe@example.com");
    expect(actorLabel("token:3f2a9c1b")).toBe("Console token 3f2a9c1b");
    expect(actorLabel("break-glass:3f2a9c1b")).toBe("Break-glass token 3f2a9c1b");
    expect(auditSummary(entry({ action: "sign_in", target: "console", detail: { role: "operator" } })))
      .toBe("Single sign-on as operator");
  });

  it("says which SIEMs a test event or a retry was for", async () => {
    expect(auditSummary(entry({ action: "test_export", target: "exports", detail: { sinks: ["sentinel", "splunk"] } })))
      .toBe("Microsoft Sentinel and Splunk");
    expect(auditSummary(entry({ action: "retry_exports", target: "syslog" }))).toBe("Syslog");
    const api = fakeApi({ audit: vi.fn(async () => [entry({ action: "test_export", target: "exports", detail: { sinks: ["syslog"] } })]) });
    render(<ApiContext.Provider value={api}><MemoryRouter><ActivityView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findByText("Sent a SIEM test event")).toBeInTheDocument();
  });

  it("shows an empty state", async () => {
    render(<ApiContext.Provider value={fakeApi()}><MemoryRouter><ActivityView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findByText("No activity yet")).toBeInTheDocument();
  });

  it("names what the server did itself", async () => {
    const api = fakeApi({ audit: vi.fn(async () => [
      entry({ id: "a3", actor: "altiward:server", action: "remove_device", target: "C02XK0AAJGH5" }),
      entry({ id: "a4", actor: "altiward:server", action: "expire_history", target: "history", at: "2026-10-17T10:00:00Z" }),
    ]) });
    render(<ApiContext.Provider value={api}><MemoryRouter><ActivityView /></MemoryRouter></ApiContext.Provider>);
    expect(await screen.findByText("Removed a Mac")).toBeInTheDocument();
    expect(screen.getByText("Removed old history")).toBeInTheDocument();
    expect(screen.getAllByText("Altiward")).toHaveLength(2);
    expect(screen.queryByText("altiward:server")).toBeNull();
    expect(actorLabel("altiward:server")).toBe("Altiward");
  });
});
