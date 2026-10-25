import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { ApiContext } from "../context";
import { fakeApi, session } from "../test/fixtures";
import { SessionsView } from "./Sessions";

const ended = session({
  session_id: "s-ended", local_user: "alice", upn: null, open: false, ended_at: "2026-10-16T08:30:00Z",
  end_reason: "remote_revoke", actual_seconds: 900,
});

function renderWith(api = fakeApi()) {
  render(
    <ApiContext.Provider value={api}>
      <MemoryRouter><SessionsView /></MemoryRouter>
    </ApiContext.Provider>,
  );
  return api;
}

describe("Sessions", () => {
  it("starts with the search the link gave", async () => {
    render(
      <ApiContext.Provider value={fakeApi({ sessions: vi.fn(async () => [session(), ended]) })}>
        <MemoryRouter initialEntries={["/sessions?q=alice"]}><SessionsView /></MemoryRouter>
      </ApiContext.Provider>,
    );
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.queryByText(/jane\.doe/)).toBeNull();
    expect(screen.getByRole("searchbox")).toHaveValue("alice");
  });

  it("explains states and flags: hover hints in the list, help tags in the details", async () => {
    const flagged = session({ flags: ["persistence_detected"], verified: false });
    renderWith(fakeApi({
      sessions: vi.fn(async () => [flagged]),
      session: vi.fn(async () => ({ session: flagged, events: [] })),
    }));
    const row = (await screen.findByText("jane.doe@example.com")).closest("tr")!;
    expect(within(row).getByText("Elevated").closest(".badge")).toHaveAttribute("title", expect.stringMatching(/held now/));
    expect(within(row).getByText("New persistence")).toHaveAttribute("title", expect.stringMatching(/keep access/));
    // No help tags in the rows: they would add a Tab stop to every row.
    expect(within(row).queryByRole("tooltip", { hidden: true })).toBeNull();

    await userEvent.click(row);
    const details = screen.getByRole("complementary", { name: "Session details" });
    expect(within(details).getByText("Claimed").closest(".explain")).toHaveAccessibleDescription(/didn’t match/);
    expect(within(details).getAllByText("New persistence")[0].closest(".explain")).toHaveAccessibleDescription(/keep access/);
    expect(within(details).getByText("Privileges")).toHaveAccessibleDescription(/SAP Privileges/);
  });

  it("revokes an active session after confirmation", async () => {
    const api = renderWith(fakeApi({
      sessions: vi.fn(async () => [session(), ended]),
      session: vi.fn(async () => ({ session: session(), events: [] })),
      revokeSession: vi.fn(async () => ({ command_id: "c1", status: "pending" }) as never),
    }));
    const user = userEvent.setup();

    await user.click(await screen.findByText("jane.doe@example.com"));
    const inspector = screen.getByRole("complementary", { name: "Session details" });
    await user.click(within(inspector).getByRole("button", { name: "Revoke admin rights…" }));

    const sheet = screen.getByRole("dialog", { name: "Revoke admin rights for jane.doe@example.com?" });
    expect(within(sheet).getByRole("button", { name: "Cancel" })).toHaveFocus();
    await user.click(within(sheet).getByRole("button", { name: "Revoke" }));

    expect(api.revokeSession).toHaveBeenCalledWith("s-open");
    expect(await screen.findByRole("status")).toHaveTextContent("Revoke sent");
  });

  it.each([
    [{ status: "completed", revoked: ["jdoe"] }, "status", "Admin rights removed from jane.doe@example.com on C02XK0AAJGH5."],
    [{ status: "failed", failed: [{ user: "jdoe", error: "still an admin" }] }, "alert",
      "C02XK0AAJGH5 couldn’t remove admin rights. jdoe: still an admin"],
    [{ status: "skipped", skipped: [{ user: "jdoe", reason: "not_admin" }] }, "status",
      "C02XK0AAJGH5 had nothing to remove. Kept jdoe (not an admin)"],
  ] as const)("reports what the Mac did with the revoke (%o)", async (result, role, text) => {
    const pending = { command_id: "c1", serial: "C02XK0AAJGH5", status: "pending", result: null };
    const done = {
      ...pending, status: result.status,
      result: { error: null, revoked: [], failed: [], skipped: [], completed_at: "2026-10-16T09:20:00Z", ...result },
    };
    const api = renderWith(fakeApi({
      sessions: vi.fn(async () => [session()]),
      session: vi.fn(async () => ({ session: session(), events: [] })),
      revokeSession: vi.fn(async () => pending as never),
      command: vi.fn(async () => done as never),
    }));
    const user = userEvent.setup();
    await user.click(await screen.findByText("jane.doe@example.com"));
    await user.click(screen.getByRole("button", { name: "Revoke admin rights…" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Revoke" }));

    expect(await screen.findByRole(role, {}, { timeout: 5000 })).toHaveTextContent(text);
    expect(api.command).toHaveBeenCalledWith("c1");
  });

  it("offers no revoke for a permanent admin", async () => {
    const permanent = session({ local_user: "itadmin", upn: null, permanent_admin: true });
    renderWith(fakeApi({
      sessions: vi.fn(async () => [permanent]),
      session: vi.fn(async () => ({ session: permanent, events: [] })),
    }));
    await userEvent.click(await screen.findByText("itadmin"));
    const inspector = screen.getByRole("complementary", { name: "Session details" });
    expect(within(inspector).queryByRole("button", { name: /Revoke/ })).toBeNull();
    expect(within(inspector).getByText(
      "itadmin is a permanent admin on this Mac, so Altiward doesn’t remove their rights.")).toBeInTheDocument();
  });

  it("offers no revoke for a session that has ended", async () => {
    renderWith(fakeApi({
      sessions: vi.fn(async () => [ended]),
      session: vi.fn(async () => ({ session: ended, events: [] })),
    }));
    await userEvent.click(await screen.findByText("alice"));
    const inspector = screen.getByRole("complementary", { name: "Session details" });
    expect(within(inspector).getByText("Revoked from the console")).toBeInTheDocument();
    expect(within(inspector).queryByRole("button", { name: /Revoke/ })).toBeNull();
  });

  it.each([
    ["privileges", "Verified"],
    ["out_of_band", null],
  ] as const)("shows the verification badge for %s sessions", async (source, badge) => {
    const s = session({ source });
    renderWith(fakeApi({
      sessions: vi.fn(async () => [s]),
      session: vi.fn(async () => ({ session: s, events: [] })),
    }));
    await userEvent.click(await screen.findByText("jane.doe@example.com"));
    const inspector = screen.getByRole("complementary", { name: "Session details" });
    if (badge) expect(within(inspector).getByText(badge)).toBeInTheDocument();
    else expect(within(inspector).queryByText(/^(Verified|Claimed)$/)).toBeNull();
  });

  it("lists what a persistence event found", async () => {
    const flagged = session({ flags: ["persistence_detected"] });
    renderWith(fakeApi({
      sessions: vi.fn(async () => [flagged]),
      session: vi.fn(async () => ({
        session: flagged,
        events: [{
          event_id: "e1", type: "persistence.detected", timestamp: "2026-10-16T09:31:47Z",
          received_at: "2026-10-16T09:31:48Z", delayed: false, user: { local_name: "jdoe", upn: null },
          elevation: { reason: null, expires: null, source: "privileges" },
          detail: {
            findings: [{ kind: "launch_daemon", change: "added", path: "/Library/LaunchDaemons/com.example.updater.plist" }],
            since: "2026-10-16T09:14:03Z", truncated: 0,
          },
        }],
      })),
    }));
    await userEvent.click(await screen.findByText("jane.doe@example.com"));
    const inspector = screen.getByRole("complementary", { name: "Session details" });
    expect(await within(inspector).findByText("New LaunchDaemon /Library/LaunchDaemons/com.example.updater.plist")).toBeInTheDocument();
    expect(within(inspector).getAllByText("New persistence")).toHaveLength(2); // the flag and the event
  });

  it("says whether Privileges’ own log confirmed a grant", async () => {
    const s = session();
    const grant = (id: string, detail: Record<string, unknown>) => ({
      event_id: id, type: "elevation.granted", timestamp: "2026-10-16T09:31:47Z",
      received_at: "2026-10-16T09:31:48Z", delayed: false, user: { local_name: "jdoe", upn: null },
      elevation: { reason: null, expires: null, source: "privileges" }, detail,
    });
    renderWith(fakeApi({
      sessions: vi.fn(async () => [s]),
      session: vi.fn(async () => ({
        session: s,
        events: [
          grant("e1", { privileges_log: "confirmed" }),
          grant("e2", { privileges_log: "not_confirmed", renewed: true }),
          grant("e3", { privileges_log: "unavailable", renewed: true }),
          grant("e4", {}),
        ],
      })),
    }));
    await userEvent.click(await screen.findByText("jane.doe@example.com"));
    const inspector = screen.getByRole("complementary", { name: "Session details" });
    expect(await within(inspector).findByText("Confirmed by Privileges’ log")).toBeInTheDocument();
    expect(within(inspector).getByText("Not confirmed by Privileges’ log")).toBeInTheDocument();
    // Placed before the renewal note, which then gives way; unavailable falls through to it.
    expect(within(inspector).getAllByText("Renewal")).toHaveLength(1);
  });

  it("filters to active sessions", async () => {
    renderWith(fakeApi({ sessions: vi.fn(async () => [session(), ended]) }));
    await screen.findByText("alice");
    await userEvent.click(screen.getByRole("button", { name: "Elevated" }));
    expect(screen.queryByText("alice")).toBeNull();
    expect(screen.getByText("jane.doe@example.com")).toBeInTheDocument();
  });
});
