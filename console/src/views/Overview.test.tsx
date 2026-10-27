import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import type { Overview, Role } from "../api";
import { ApiContext, MeContext } from "../context";
import { fakeApi, githubFetch, overview, signedIn } from "../test/fixtures";
import { setShowPrereleases } from "../updates";
import { OverviewView } from "./Overview";

const busy = (): Overview => {
  const base = overview();
  return overview({
    now: { admins: 10, privileges: 9, without_grant: 1, past_expiry: 1, macs_failing_checks: 2, macs_silent: 0 },
    period: {
      ...base.period,
      elevations: 12, without_grant: 1,
      buckets: base.period.buckets.map((b, i) => ({ ...b, privileges: i, without_grant: i === 6 ? 1 : 0 })),
      durations: [
        { source: "privileges", ended: 8, given_back_early: 4, median_held_seconds: 600, median_allowed_seconds: 1200 },
      ],
      top_users: [
        { name: "jane.doe@example.com", elevations: 5, macs: 2 },
        { name: "admin", serial: "C02XK0AAJGH5", elevations: 3, macs: 1 },
      ],
      top_macs: [{ serial: "C02XK0AAJGH5", elevations: 7, people: 2 }],
    },
    health: {
      macs: 40, agents_outdated: 1,
      agent_versions: [{ version: "0.1.2", macs: 39, supported: true }, { version: "0.0.4", macs: 1, supported: false }],
      sinks: [
        { sink: "sentinel", state: "delivering", pending: 0, failing: 0, oldest_queued_at: null, max_attempts: 0, last_delivered_at: new Date().toISOString() },
        { sink: "splunk", state: "behind", pending: 412, failing: 0, oldest_queued_at: null, max_attempts: 0, last_delivered_at: null },
      ],
    },
  });
};

function renderWith(api = fakeApi({ overview: vi.fn(async () => busy()) })) {
  render(<ApiContext.Provider value={api}><MemoryRouter><OverviewView /></MemoryRouter></ApiContext.Provider>);
  return api;
}

describe("Overview", () => {
  it("sums up who holds admin rights and what needs a look", async () => {
    renderWith();
    expect(await screen.findByText("10 people have admin rights now, 1 without a grant. 3 things need a look.")).toBeInTheDocument();
    const now = screen.getByRole("region", { name: "Now" });
    expect(within(now).getByText("10")).toBeInTheDocument();
    expect(within(now).getByRole("link", { name: "Rights past their expiry: show 1 person" })).toHaveAttribute("href", "/admins");
    expect(within(now).getByRole("link", { name: "Macs failing an integrity check: show 2 Macs" }))
      .toHaveAttribute("href", "/fleet?show=attention");
    // Nothing to look at says so, with no link.
    expect(within(now).getByText("None")).toBeInTheDocument();
    expect(within(now).queryByRole("link", { name: /Macs not checking in/ })).toBeNull();
  });

  it("explains its terms in help tags", async () => {
    renderWith();
    expect((await screen.findAllByText("Without a grant"))[0]).toHaveAccessibleDescription(/nobody granted through Privileges/);
    expect(screen.getByText("Admins now")).toHaveAccessibleDescription(/Permanent admins/);
    const median = screen.getByText("Median");
    expect(median).toHaveAccessibleDescription(/middle value/);
    expect(median).toHaveAttribute("tabindex", "0");
  });

  it("shows the period's elevations, time held and who elevates most", async () => {
    renderWith();
    const period = await screen.findByRole("region", { name: /Elevations/ });
    expect(within(period).getByText("Last 7 days")).toBeInTheDocument();
    expect(within(period).getByText("12")).toBeInTheDocument();
    expect(within(period).getByText(/10 min of 20 min, 50%/)).toBeInTheDocument();
    expect(within(period).getByRole("link", { name: "jane.doe@example.com" })).toHaveAttribute("href", "/sessions?q=jane.doe%40example.com");
    expect(within(period).getByRole("link", { name: "C02XK0AAJGH5" })).toHaveAttribute("href", "/fleet?q=C02XK0AAJGH5");
    // Screen readers get the chart as a table.
    expect(within(period).getByRole("table", { name: "Elevations per day by source" })).toBeInTheDocument();
  });

  it("shows agent versions and each SIEM's state in words", async () => {
    renderWith();
    const health = await screen.findByRole("region", { name: "Health" });
    expect(within(health).getByText("Unsupported")).toBeInTheDocument();
    expect(within(health).getByRole("link", { name: "Show the 1 Mac to update" })).toHaveAttribute("href", "/fleet?show=outdated");
    expect(within(health).getByText("Microsoft Sentinel")).toBeInTheDocument();
    expect(within(health).getByText("Delivering")).toBeInTheDocument();
    expect(within(health).getByText("Behind")).toBeInTheDocument();
    expect(within(health).getByText("Never")).toBeInTheDocument();
  });

  it("asks the server for the period chosen", async () => {
    const api = renderWith(fakeApi({ overview: vi.fn(async () => overview()) }));
    await screen.findByText("No one has admin rights now. Nothing needs a look.");
    expect(screen.getByText("None ended yet")).toBeInTheDocument();
    expect(api.overview).toHaveBeenLastCalledWith(30);
    await userEvent.click(screen.getByRole("button", { name: "90 days" }));
    expect(api.overview).toHaveBeenLastCalledWith(90);
    expect(screen.getByText(/No SIEM is set up/)).toBeInTheDocument();
  });
});

describe("Overview update notice", () => {
  const github = (fetch: ReturnType<typeof vi.fn>) =>
    fetch.mock.calls.filter(([url]) => String(url).startsWith("https://api.github.com/"));

  function renderAs(role: Role, { updateCheck = true, version = "0.1.0", agents = ["0.1.0"] } = {}) {
    const api = fakeApi({
      about: vi.fn(async () => ({ version, oldest_supported_agent: "0.1", update_check: updateCheck })),
      overview: vi.fn(async () => overview({
        health: { macs: 1, agents_outdated: 0, agent_versions: agents.map((v) => ({ version: v, macs: 1, supported: true })), sinks: [] },
      })),
    });
    render(<ApiContext.Provider value={api}><MeContext.Provider value={signedIn(role)}>
      <MemoryRouter><OverviewView /></MemoryRouter>
    </MeContext.Provider></ApiContext.Provider>);
    return api;
  }

  it("tells an admin a newer server and agent are out, and how to install them", async () => {
    const fetch = githubFetch();
    renderAs("admin");
    const notice = await screen.findByRole("region", { name: "Server 0.2.0 is available" });
    expect(within(notice).getByText("Server 0.2.0 is available. You’re running 0.1.0.")).toBeInTheDocument();
    expect(within(notice).getByText("Security")).toBeInTheDocument();
    expect(within(notice).getByRole("link", { name: "Release notes for 0.2.0" }))
      .toHaveAttribute("href", "https://github.com/Altiward/altiward/releases/tag/server-v0.2.0");
    expect(within(notice).getByText("./upgrade.sh 0.2.0")).toBeInTheDocument();
    expect(within(notice).getByText(/On a server without internet access, put the release files in a directory/)).toBeInTheDocument();
    expect(within(notice).getByRole("button", { name: "Copy" })).toBeInTheDocument();

    const agent = screen.getByRole("region", { name: "Agent 0.2.0 is available" });
    expect(within(agent).getByText(/Roll it out through your MDM after the server\./)).toBeInTheDocument();
    expect(within(agent).getByRole("link", { name: "Download Altiward-0.2.0.pkg" }))
      .toHaveAttribute("href", "https://github.com/Altiward/altiward/releases/download/agent-v0.2.0/Altiward-0.2.0.pkg");
    expect(within(agent).queryByText("Security")).toBeNull();
    expect(github(fetch)).toHaveLength(1);
  });

  it("tells an admin on Azure Container Apps which image to change to", async () => {
    githubFetch();
    const api = fakeApi({
      about: vi.fn(async () => ({ version: "0.1.0", oldest_supported_agent: "0.1", update_check: true,
        platform: "azure-container-apps" as const, app: "altiwardlab" })),
    });
    render(<ApiContext.Provider value={api}><MeContext.Provider value={signedIn("admin")}>
      <MemoryRouter><OverviewView /></MemoryRouter>
    </MeContext.Provider></ApiContext.Provider>);
    const notice = await screen.findByRole("region", { name: "Server 0.2.0 is available" });
    expect(within(notice).getByText("ghcr.io/altiward/altiward-api:0.2.0")).toBeInTheDocument();
    expect(within(notice).getByText("altiwardlab")).toBeInTheDocument();
    expect(within(notice).queryByText(/upgrade\.sh/)).toBeNull();
    expect(within(notice).getByRole("link", { name: "how to upgrade" }))
      .toHaveAttribute("href", "https://github.com/Altiward/altiward/blob/server-v0.2.0/deploy/azure/README.md#upgrading");
  });

  it("can be dismissed for that version", async () => {
    githubFetch();
    renderAs("admin");
    const notice = await screen.findByRole("region", { name: "Server 0.2.0 is available" });
    await userEvent.click(within(notice).getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByRole("region", { name: "Server 0.2.0 is available" })).toBeNull();
    expect(screen.getByRole("region", { name: "Agent 0.2.0 is available" })).toBeInTheDocument();
  });

  it("says nothing when the server is up to date", async () => {
    githubFetch();
    const api = renderAs("admin", { version: "0.2.0", agents: ["0.2.0"] });
    await screen.findByText("No one has admin rights now. Nothing needs a look.");
    await waitFor(() => expect(api.about).toHaveBeenCalled());
    expect(screen.queryByText(/is available/)).toBeNull();
  });

  it("tells an admin who shows pre-releases about a release candidate", async () => {
    githubFetch();
    setShowPrereleases(true);
    renderAs("admin", { version: "0.2.0", agents: ["0.2.0"] });
    const notice = await screen.findByRole("region", { name: "Server release candidate 0.3.0-rc.1 is available" });
    expect(within(notice).getByText("Server release candidate 0.3.0-rc.1 is available. You’re running 0.2.0.")).toBeInTheDocument();
    expect(within(notice).getByText("./upgrade.sh 0.3.0-rc.1")).toBeInTheDocument();
  });

  it("isn't shown to a viewer, who never asks GitHub", async () => {
    const fetch = githubFetch();
    const api = renderAs("viewer");
    await screen.findByText("No one has admin rights now. Nothing needs a look.");
    expect(screen.queryByText(/is available/)).toBeNull();
    expect(api.about).not.toHaveBeenCalled();
    expect(github(fetch)).toHaveLength(0);
  });

  it("asks GitHub nothing when the server turned the check off", async () => {
    const fetch = githubFetch();
    const api = renderAs("admin", { updateCheck: false });
    await screen.findByText("No one has admin rights now. Nothing needs a look.");
    await waitFor(() => expect(api.about).toHaveBeenCalled());
    expect(screen.queryByText(/is available/)).toBeNull();
    expect(github(fetch)).toHaveLength(0);
  });

  it("shows nothing when GitHub can't be reached", async () => {
    const fetch = githubFetch("offline");
    renderAs("admin");
    await screen.findByText("No one has admin rights now. Nothing needs a look.");
    await waitFor(() => expect(github(fetch)).toHaveLength(1));
    expect(screen.queryByText(/is available/)).toBeNull();
    expect(screen.queryByText(/Couldn.t check/)).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
