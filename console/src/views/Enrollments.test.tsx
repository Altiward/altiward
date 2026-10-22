import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { JSX } from "react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import type { Enrollment } from "../api";
import { ApiContext } from "../context";
import { fakeApi, session } from "../test/fixtures";
import { AdminsNowView } from "./AdminsNow";
import { EnrollmentsView } from "./Enrollments";

const pending: Enrollment = {
  device_id: "d-pending", serial: "C02XK0AAJGH5", hardware_uuid: "HW-1", public_key: btoa("abc"),
  status: "pending", created_at: "2026-10-16T11:00:00Z", activated_at: null, revoked_at: null,
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
