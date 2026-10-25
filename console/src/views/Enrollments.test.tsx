import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { JSX } from "react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import type { Device, Enrollment } from "../api";
import { ApiContext } from "../context";
import { fakeApi, session } from "../test/fixtures";
import { AdminsNowView } from "./AdminsNow";
import { EnrollmentsView } from "./Enrollments";

const pending: Enrollment = {
  device_id: "d-pending", serial: "C02XK0AAJGH5", hardware_uuid: "HW-1", public_key: btoa("abc"),
  key_storage: "secure_enclave", status: "pending", created_at: "2026-10-16T11:00:00Z", activated_at: null, revoked_at: null,
};

function renderView(api: ReturnType<typeof fakeApi>, view: JSX.Element) {
  render(<ApiContext.Provider value={api}><MemoryRouter>{view}</MemoryRouter></ApiContext.Provider>);
}

describe("Enrollments", () => {
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
