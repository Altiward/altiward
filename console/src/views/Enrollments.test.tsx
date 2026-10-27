import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { JSX } from "react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type Device, type Enrollment } from "../api";
import { ApiContext } from "../context";
import { shortFingerprint } from "../format";
import { enrollment, fakeApi, session } from "../test/fixtures";
import { AdminsNowView } from "./AdminsNow";
import { EnrollmentsView } from "./Enrollments";

const pending: Enrollment = {
  device_id: "d-pending", serial: "C02XK0AAJGH5", hardware_uuid: "HW-1", public_key: btoa("abc"),
  key_storage: "secure_enclave", token: "token:1a2b3c4d", status: "pending", created_at: "2026-10-16T11:00:00Z", activated_at: null,
  revoked_at: null,
};

function renderView(api: ReturnType<typeof fakeApi>, view: JSX.Element) {
  render(<ApiContext.Provider value={api}><MemoryRouter>{view}</MemoryRouter></ApiContext.Provider>);
}

describe("Enrollments", () => {
  it("loads and polls Fleet evidence only for a selected pending key", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      const active: Enrollment = { ...pending, serial: "ACTIVE-MAC", device_id: "d-active", status: "active" };
      const api = fakeApi({ enrollments: vi.fn(async () => [pending, active]), devices: vi.fn(async () => []) });
      renderView(api, <EnrollmentsView />);
      await screen.findByText("ACTIVE-MAC");
      expect(api.devices).not.toHaveBeenCalled();
      await userEvent.click(screen.getByText("ACTIVE-MAC"));
      expect(api.devices).not.toHaveBeenCalled();
      await userEvent.click(screen.getByText(pending.serial));
      await waitFor(() => expect(api.devices).toHaveBeenCalledTimes(1));
      await act(async () => { vi.advanceTimersByTime(30_000); });
      expect(api.devices).toHaveBeenCalledTimes(2);
      await userEvent.click(screen.getByRole("button", { name: "Close details" }));
      await act(async () => { vi.advanceTimersByTime(30_000); });
      expect(api.devices).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("approves a pending re-enrollment and shows its key fingerprint", async () => {
    const api = fakeApi({
      enrollments: vi.fn(async () => [pending]),
      approveEnrollment: vi.fn(async () => ({ ...pending, status: "active" as const })),
    });
    renderView(api, <EnrollmentsView />);
    await userEvent.click(await screen.findByText("C02XK0AAJGH5"));
    const inspector = screen.getByRole("complementary", { name: "Enrollment details" });
    expect(await within(inspector).findByText("BA78 16BF 8F01 CFEA")).toBeInTheDocument();
    await userEvent.click(within(inspector).getByRole("button", { name: "Approve" }));
    expect(api.approveEnrollment).toHaveBeenCalledWith("d-pending");
    expect(await screen.findByRole("status")).toHaveTextContent("Approved");
  });
});

describe("Enrollments, the token that enrolled a key", () => {
  it("shows the token's fingerprint, or says it wasn't recorded", async () => {
    const older: Enrollment = { ...pending, device_id: "d-older", serial: "OLDER-MAC", status: "active", token: "" };
    renderView(fakeApi({ enrollments: vi.fn(async () => [pending, older]) }), <EnrollmentsView />);
    await userEvent.click(await screen.findByText(pending.serial));
    expect(screen.getByRole("complementary", { name: "Enrollment details" })).toHaveTextContent("Enrolled withtoken:1a2b3c4d");
    await userEvent.click(screen.getByText("OLDER-MAC"));
    expect(screen.getByRole("complementary", { name: "Enrollment details" })).toHaveTextContent("Enrolled withNot recorded");
  });

  it("finds every key one token enrolled", async () => {
    const other: Enrollment = { ...pending, device_id: "d-other", serial: "OTHER-MAC", token: "token:99999999" };
    renderView(fakeApi({ enrollments: vi.fn(async () => [pending, other]) }), <EnrollmentsView />);
    await screen.findByText("OTHER-MAC");
    await userEvent.type(screen.getByRole("searchbox"), "1a2b3c4d");
    expect(screen.getByText(pending.serial)).toBeInTheDocument();
    expect(screen.queryByText("OTHER-MAC")).toBeNull();
  });
});

describe("Enrollments, telling new Macs from re-enrollments", () => {
  const openPending = async () => {
    const rows = await screen.findAllByText("C02XK0AAJGH5");
    await userEvent.click(rows.find((r) => r.closest("tr")?.textContent?.includes("Waiting"))!);
    return screen.getByRole("complementary", { name: "Enrollment details" });
  };


  it("approves a new Mac however many are enrolled, with no mention of a limit", async () => {
    const others: Enrollment[] = Array.from({ length: 30 }, (_, i) => ({
      ...pending, device_id: `d-${i}`, serial: `SERIAL${i}`, status: "active" as const, activated_at: "2026-10-01T00:00:00Z",
    }));
    renderView(fakeApi({ enrollments: vi.fn(async () => [pending, ...others]) }), <EnrollmentsView />);
    const inspector = await openPending();
    expect(within(inspector).getByRole("button", { name: "Approve" })).toBeEnabled();
    expect(inspector).toHaveTextContent("This Mac is waiting for approval.");
    expect(inspector).not.toHaveTextContent(/licen[cs]e|limit|pricing/i);
    expect(within(inspector).queryByRole("link", { name: "Pricing" })).toBeNull();
  });

  it("counts a Mac whose earlier key was revoked as new", async () => {
    const revoked: Enrollment = { ...pending, device_id: "d-old", status: "revoked", revoked_at: "2026-10-10T00:00:00Z" };
    renderView(fakeApi({ enrollments: vi.fn(async () => [pending, revoked]) }), <EnrollmentsView />);
    const inspector = await openPending();
    expect(within(inspector).getByRole("button", { name: "Approve" })).toBeEnabled();
    expect(inspector).toHaveTextContent("This Mac is waiting for approval.");
  });

  it("explains a re-enrollment of a Mac that already has an active key", async () => {
    const active: Enrollment = { ...pending, device_id: "d-active", status: "active", activated_at: "2026-10-01T00:00:00Z" };
    renderView(fakeApi({ enrollments: vi.fn(async () => [pending, active]) }), <EnrollmentsView />);
    const inspector = await openPending();
    expect(within(inspector).getByRole("button", { name: "Approve" })).toBeEnabled();
    expect(inspector).toHaveTextContent("This Mac enrolled again with a new key.");
  });
});

describe("Enrollments, where each key is kept", () => {
  const macs: Enrollment[] = [
    { ...pending, device_id: "d-se", serial: "SERIAL-SE", status: "active", activated_at: "2026-10-01T00:00:00Z" },
    { ...pending, device_id: "d-file", serial: "SERIAL-FILE", key_storage: "software", status: "active",
      activated_at: "2026-10-01T00:00:00Z" },
    { ...pending, device_id: "d-old", serial: "SERIAL-OLD", key_storage: "", status: "active", activated_at: "2026-10-01T00:00:00Z" },
  ];
  const row = (serial: string) => screen.getByText(serial).closest("tr")!;

  it("shows a word for each, and suggests revoking a file key", async () => {
    renderView(fakeApi({ enrollments: vi.fn(async () => macs) }), <EnrollmentsView />);
    await screen.findByText("SERIAL-SE");
    expect(row("SERIAL-SE")).toHaveTextContent("Secure Enclave");
    expect(row("SERIAL-FILE")).toHaveTextContent("File");
    expect(row("SERIAL-OLD")).toHaveTextContent("Not reported");

    await userEvent.click(screen.getByText("SERIAL-FILE"));
    const inspector = screen.getByRole("complementary", { name: "Enrollment details" });
    expect(inspector).toHaveTextContent("This key is in a file");
    await userEvent.click(within(inspector).getByRole("button", { name: "Close details" }));
    await userEvent.click(screen.getByText("SERIAL-SE"));
    expect(screen.getByRole("complementary", { name: "Enrollment details" })).not.toHaveTextContent("This key is in a file");
  });

  it("warns when a new file key would replace a Secure Enclave key", async () => {
    const active: Enrollment = { ...pending, device_id: "d-active", status: "active", activated_at: "2026-10-01T00:00:00Z" };
    const fileKey: Enrollment = { ...pending, key_storage: "software" };
    renderView(fakeApi({ enrollments: vi.fn(async () => [fileKey, active]) }), <EnrollmentsView />);
    const rows = await screen.findAllByText("C02XK0AAJGH5");
    await userEvent.click(rows.find((r) => r.closest("tr")?.textContent?.includes("Waiting"))!);
    expect(screen.getByRole("complementary", { name: "Enrollment details" }))
      .toHaveTextContent("The key this Mac uses now is in the Secure Enclave, but this new one isn’t.");
  });
});

describe("Enrollments, the evidence for a pending key", () => {
  const active: Enrollment = { ...pending, device_id: "d-active", status: "active", activated_at: "2026-10-01T00:00:00Z" };
  const mac = (over: Partial<Device> = {}): Device => ({
    serial: "C02XK0AAJGH5", hardware_uuid: "HW-1", os_version: "26.1.0", agent_version: "0.5.0", privileges_version: "2.6.0",
    first_seen_at: "2026-10-01T00:00:00Z", last_seen_at: "2026-10-01T00:00:00Z", last_health_at: null,
    admin_members: [], queue_depth: 0, privileges: {}, ...over,
  });
  const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000).toISOString();
  const openPending = async () => {
    const rows = await screen.findAllByText("C02XK0AAJGH5");
    await userEvent.click(rows.find((r) => r.closest("tr")?.textContent?.includes("Waiting"))!);
    return screen.getByRole("complementary", { name: "Enrollment details" });
  };

  it("hides a previous check-in when a later Fleet refresh fails", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      const devices = vi.fn().mockResolvedValueOnce([mac({ last_received_at: minutesAgo(4) })])
        .mockRejectedValue(new Error("devices are down"));
      renderView(fakeApi({ enrollments: vi.fn(async () => [pending, active]), devices }), <EnrollmentsView />);
      const inspector = await openPending();
      expect(await within(inspector).findByText(/last checked in 4 min ago/)).toBeInTheDocument();
      await act(async () => { vi.advanceTimersByTime(30_000); });
      await waitFor(() => expect(inspector).not.toHaveTextContent("last checked in"));
      expect(within(inspector).getByRole("button", { name: "Approve" })).toBeEnabled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("says when the Mac last checked in with its current key", async () => {
    renderView(fakeApi({
      enrollments: vi.fn(async () => [pending, active]),
      devices: vi.fn(async () => [mac({ last_received_at: minutesAgo(4) })]),
    }), <EnrollmentsView />);
    const inspector = await openPending();
    expect(await within(inspector).findByText("This Mac last checked in 4 min ago with its current key.")).toBeInTheDocument();
  });

  it("uses the check-in time the Fleet view shows, by the server's clock first", async () => {
    renderView(fakeApi({
      enrollments: vi.fn(async () => [pending, active]),
      devices: vi.fn(async () => [mac({ last_seen_at: minutesAgo(90), last_health_at: minutesAgo(30), last_received_at: minutesAgo(2) })]),
    }), <EnrollmentsView />);
    const inspector = await openPending();
    expect(await within(inspector).findByText("This Mac last checked in 2 min ago with its current key.")).toBeInTheDocument();
  });

  it("doesn't claim a current key when every earlier key was revoked", async () => {
    const revoked: Enrollment = { ...pending, device_id: "d-old", status: "revoked", revoked_at: "2026-10-10T00:00:00Z" };
    renderView(fakeApi({
      enrollments: vi.fn(async () => [pending, revoked]),
      devices: vi.fn(async () => [mac({ last_received_at: minutesAgo(4) })]),
    }), <EnrollmentsView />);
    const inspector = await openPending();
    expect(await within(inspector).findByText("This Mac last checked in 4 min ago.")).toBeInTheDocument();
    expect(inspector).not.toHaveTextContent("current key");
  });

  it("says so when the Mac hasn’t checked in yet", async () => {
    renderView(fakeApi({ enrollments: vi.fn(async () => [pending]), devices: vi.fn(async () => []) }), <EnrollmentsView />);
    const inspector = await openPending();
    expect(await within(inspector).findByText("This Mac hasn’t checked in yet.")).toBeInTheDocument();
    expect(inspector).not.toHaveTextContent("last checked in");
  });

  it("leaves the check-in line out when the devices don't load, and still lets you approve", async () => {
    const api = fakeApi({
      enrollments: vi.fn(async () => [pending, active]),
      devices: vi.fn(async () => { throw new Error("devices are down"); }),
      approveEnrollment: vi.fn(async () => ({ ...pending, status: "active" as const })),
    });
    renderView(api, <EnrollmentsView />);
    const inspector = await openPending();
    await waitFor(() => expect(api.devices).toHaveBeenCalled());
    expect(inspector).not.toHaveTextContent(/last checked in|hasn’t checked in/);
    expect(screen.queryByText("devices are down")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
    await userEvent.click(within(inspector).getByRole("button", { name: "Approve" }));
    expect(api.approveEnrollment).toHaveBeenCalledWith("d-pending");
  });

  it("only shows the check-in line for a key waiting for approval", async () => {
    renderView(fakeApi({
      enrollments: vi.fn(async () => [pending, active]),
      devices: vi.fn(async () => [mac({ last_received_at: minutesAgo(4) })]),
    }), <EnrollmentsView />);
    const pendingInspector = await openPending();
    // The devices have loaded once the pending key shows its line.
    expect(await within(pendingInspector).findByText(/last checked in 4 min ago/)).toBeInTheDocument();
    await userEvent.click(within(pendingInspector).getByRole("button", { name: "Close details" }));

    const rows = screen.getAllByText("C02XK0AAJGH5");
    await userEvent.click(rows.find((r) => r.closest("tr")?.textContent?.includes("Active"))!);
    const activeInspector = screen.getByRole("complementary", { name: "Enrollment details" });
    expect(within(activeInspector).getByText("Key kept in")).toBeInTheDocument();
    expect(activeInspector).not.toHaveTextContent("checked in");
  });

  it("warns, with a word and a glyph, when the new key reports different hardware", async () => {
    const changed: Enrollment = { ...pending, hardware_uuid: "HW-NEW" };
    renderView(fakeApi({
      enrollments: vi.fn(async () => [changed, { ...active, hardware_uuid: "HW-OLD" }]),
    }), <EnrollmentsView />);
    const inspector = await openPending();
    const warning = within(inspector).getByText(
      "The new key reports a different hardware UUID (HW-NEW, was HW-OLD). Expect this only after a logic board replacement.",
    );
    const tag = warning.closest("p")!.querySelector(".tag")!;
    expect(tag).toHaveTextContent("Warning");
    expect(tag.querySelector("svg")).not.toBeNull();
  });

  it("puts the hardware warning before the buttons, and doesn't suggest a reinstall", async () => {
    const changed: Enrollment = { ...pending, hardware_uuid: "HW-NEW" };
    renderView(fakeApi({
      enrollments: vi.fn(async () => [changed, { ...active, hardware_uuid: "HW-OLD" }]),
    }), <EnrollmentsView />);
    const inspector = await openPending();
    const warning = within(inspector).getByText(/different hardware UUID/).closest("p")!;
    const approve = within(inspector).getByRole("button", { name: "Approve" });
    expect(warning.compareDocumentPosition(approve) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(inspector).toHaveTextContent("This Mac enrolled again with a new key.");
    expect(inspector).not.toHaveTextContent("reinstall");
  });

  it("doesn't warn when the hardware is the same, and suggests a reinstall", async () => {
    renderView(fakeApi({ enrollments: vi.fn(async () => [pending, active]) }), <EnrollmentsView />);
    const inspector = await openPending();
    expect(inspector).not.toHaveTextContent("different hardware UUID");
    expect(inspector).toHaveTextContent("Approve it if you expect that, for example after a reinstall.");
  });

  it("doesn't warn when there is no active key to compare with", async () => {
    renderView(fakeApi({ enrollments: vi.fn(async () => [{ ...pending, hardware_uuid: "HW-NEW" }]) }), <EnrollmentsView />);
    expect(await openPending()).not.toHaveTextContent("different hardware UUID");
  });

  it("compares with this Mac's active key, not another Mac's", async () => {
    const other: Enrollment = { ...active, device_id: "d-other", serial: "SERIAL-OTHER", hardware_uuid: "HW-OTHER" };
    renderView(fakeApi({ enrollments: vi.fn(async () => [pending, active, other]) }), <EnrollmentsView />);
    expect(await openPending()).not.toHaveTextContent("different hardware UUID");
  });
});

describe("Enrollments, rotated keys", () => {
  // A Mac that rotated once: its first key is stale, and its second is the key in use.
  const stale = enrollment({
    device_id: "d-stale", serial: "ROTATED-MAC", public_key: btoa("first key"), status: "revoked",
    revoked_at: "2026-10-20T08:00:00Z", rotated_to: "d-current",
  });
  const current = enrollment({
    device_id: "d-current", serial: "ROTATED-MAC", public_key: btoa("second key"), key_storage: "software",
    created_at: "2026-10-20T08:00:00Z", activated_at: "2026-10-20T08:00:00Z", rotated_from: "d-stale",
  });
  const plainRevoked = enrollment({
    device_id: "d-lost", serial: "LOST-MAC", public_key: btoa("lost key"), status: "revoked", revoked_at: "2026-10-18T08:00:00Z",
  });
  const row = (serial: string, text: string) =>
    screen.getAllByText(serial).map((r) => r.closest("tr")!).find((r) => r.textContent?.includes(text))!;
  const inspector = () => screen.getByRole("complementary", { name: "Enrollment details" });
  const listed = (serial: string) => within(screen.getByRole("grid")).queryAllByText(serial).length;

  it("shows a stale key as Rotated, not Revoked", async () => {
    renderView(fakeApi({ enrollments: vi.fn(async () => [stale, current, plainRevoked]) }), <EnrollmentsView />);
    await screen.findAllByText("ROTATED-MAC");
    const rotated = row("ROTATED-MAC", "Rotated");
    expect(rotated).toHaveTextContent("Rotated");
    expect(rotated).not.toHaveTextContent("Revoked");
    expect(rotated.querySelector(".badge svg")).not.toBeNull();
    const revoked = screen.getByText("LOST-MAC").closest("tr")!;
    expect(revoked).toHaveTextContent("Revoked");
    expect(revoked).not.toHaveTextContent("Rotated");
    // The two words have different glyphs.
    expect(rotated.querySelector(".badge svg")!.innerHTML).not.toEqual(revoked.querySelector(".badge svg")!.innerHTML);
  });

  it("the inspector links the key in use", async () => {
    renderView(fakeApi({ enrollments: vi.fn(async () => [stale, current]) }), <EnrollmentsView />);
    await screen.findAllByText("ROTATED-MAC");
    await userEvent.click(screen.getByRole("button", { name: "Revoked" }));
    expect(listed("ROTATED-MAC")).toBe(1);
    await userEvent.click(within(screen.getByRole("grid")).getByText("ROTATED-MAC"));
    expect(inspector()).toHaveTextContent("Replaced by rotation on");
    const link = within(inspector()).getByRole("button", { name: await shortFingerprint(current.public_key) });
    await userEvent.click(link);
    expect(screen.getByRole("button", { name: "All" })).toHaveAttribute("aria-pressed", "true");
    expect(listed("ROTATED-MAC")).toBe(2);
    expect(inspector()).toHaveTextContent("Rotated from");
    expect(inspector()).toHaveTextContent("Active");
  });

  it("a key made by rotation says where it came from", async () => {
    renderView(fakeApi({ enrollments: vi.fn(async () => [stale, current]) }), <EnrollmentsView />);
    await screen.findAllByText("ROTATED-MAC");
    await userEvent.click(row("ROTATED-MAC", "Active"));
    expect(inspector()).toHaveTextContent("Rotated from");
    const fingerprint = await shortFingerprint(stale.public_key);
    await userEvent.click(within(inspector()).getByRole("button", { name: fingerprint }));
    expect(inspector()).toHaveTextContent("Replaced by rotation on");
  });

  it("a revoke from a stale page shows the key in use", async () => {
    // The page still lists the first key as active: the Mac rotated after it loaded.
    const before = enrollment({ device_id: "d-stale", serial: "ROTATED-MAC", public_key: stale.public_key });
    const api = fakeApi({
      enrollments: vi.fn().mockResolvedValueOnce([before]).mockResolvedValue([stale, current]),
      revokeEnrollment: vi.fn(async () => {
        throw new ApiError(409, "this key was rotated; revoke the key in use instead",
          { code: "credential_rotated", current_device_id: "d-current" });
      }),
    });
    renderView(api, <EnrollmentsView />);
    await userEvent.click(await screen.findByText("ROTATED-MAC"));
    await userEvent.click(within(inspector()).getByRole("button", { name: "Revoke…" }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Revoke" }));
    expect(api.revokeEnrollment).toHaveBeenCalledTimes(1);
    expect(api.revokeEnrollment).toHaveBeenCalledWith("d-stale");
    const banner = await screen.findByRole("alert");
    const fingerprint = await shortFingerprint(current.public_key);
    await waitFor(() => expect(banner).toHaveTextContent(fingerprint));
    expect(banner).toHaveTextContent("rotated");
    expect(screen.queryByText(/^Revoked the key/)).toBeNull();
    expect(screen.queryByRole("status")).toBeNull();
    // The list now shows what the server has, and the key in use is still active.
    await waitFor(() => expect(row("ROTATED-MAC", "Rotated")).toBeDefined());
    expect(row("ROTATED-MAC", "Active")).toBeDefined();
    // The banner's link goes to the key in use.
    await userEvent.click(within(banner).getByRole("button", { name: fingerprint }));
    expect(inspector()).toHaveTextContent("Rotated from");
  });

  it("the file key note says the agent moves it", async () => {
    renderView(fakeApi({ enrollments: vi.fn(async () => [current]) }), <EnrollmentsView />);
    await userEvent.click(await screen.findByText("ROTATED-MAC"));
    expect(inspector()).toHaveTextContent("This key is in a file, so someone with admin rights on the Mac could copy it");
    expect(inspector()).toHaveTextContent("The agent moves this key into the Secure Enclave by itself.");
    expect(inspector()).not.toHaveTextContent(/revoke it/i);
  });

  it("rotated rows offer no actions", async () => {
    renderView(fakeApi({ enrollments: vi.fn(async () => [stale, current]) }), <EnrollmentsView />);
    await screen.findAllByText("ROTATED-MAC");
    await userEvent.click(row("ROTATED-MAC", "Rotated"));
    expect(within(inspector()).queryByRole("button", { name: /Revoke|Reject|Approve/ })).toBeNull();
  });
});

describe("Admins Now", () => {
  it("says so when nobody holds admin rights", async () => {
    renderView(fakeApi(), <AdminsNowView />);
    expect(await screen.findByText("No one has admin rights right now")).toBeInTheDocument();
  });

  it("lists rights Privileges didn't grant", async () => {
    const api = fakeApi({
      sessions: vi.fn(async () => [session({ session_id: "s-oob", local_user: "backdoor", upn: null, source: "out_of_band",
        flags: ["out_of_band"], allowed_seconds: null, expires_at: null })]),
    });
    renderView(api, <AdminsNowView />);
    const row = (await screen.findByText("backdoor")).closest("tr")!;
    expect(within(row).getByText("Without a grant")).toBeInTheDocument();

    await userEvent.click(row);
    const inspector = screen.getByRole("complementary", { name: "Session details" });
    expect(within(inspector).getByText(/managed admin account \(LAPS\)/)).toBeInTheDocument();
    expect(within(inspector).getByRole("link", { name: "how" }))
      .toHaveAttribute("href", expect.stringContaining("docs/install.md#2-deploy-the-agent"));
  });

  it("doesn't point a Privileges grant at PermanentAdmins", async () => {
    const api = fakeApi({ sessions: vi.fn(async () => [session({ session_id: "s-priv", local_user: "asmith", upn: null })]) });
    renderView(api, <AdminsNowView />);
    await userEvent.click((await screen.findByText("asmith")).closest("tr")!);
    const inspector = screen.getByRole("complementary", { name: "Session details" });
    expect(within(inspector).queryByText(/PermanentAdmins/)).toBeNull();
  });
});
