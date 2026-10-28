import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import type { Me } from "./api";
import { overview } from "./test/fixtures";

type Server = { sso?: boolean; session?: Me | null; tokenMe?: Me; tokenStatus?: number; providerSignOutURL?: string };

const tokenMe: Me = { actor: "token:3f2a9c1b", name: "", role: "admin", method: "token" };

// App builds its own API, so the tests answer fetch as the server would.
function serve({ sso = false, session = null, tokenMe: asToken = tokenMe, tokenStatus = 200, providerSignOutURL }: Server) {
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    const path = new URL(url, "http://localhost").pathname;
    const bearer = new Headers(init?.headers).get("Authorization");
    const json = (body: unknown, status = 200) =>
      new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    switch (path) {
      case "/v1/auth/config": return json({ sso });
      case "/v1/auth/me":
        if (bearer === "Bearer console-token-000000001") return tokenStatus === 200 ? json(asToken) : json({ error: "no" }, tokenStatus);
        if (bearer) return json({ error: "bad token" }, 401);
        return session ? json(session) : json({ error: "sign in" }, 401);
      case "/v1/auth/logout":
        return providerSignOutURL ? json({ provider_sign_out_url: providerSignOutURL }) : json(null, 204);
      case "/v1/about": return json({ version: "0.1.0", oldest_supported_agent: "0.1" });
      case "/v1/enrollments": return json({ enrollments: [] });
      case "/v1/sessions": return json({ sessions: [] });
      case "/v1/devices": return json({ devices: [] });
      case "/v1/overview": return json(overview());
    }
    return json({});
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

afterEach(() => {
  sessionStorage.clear();
  window.history.replaceState(null, "", "/");
});

describe("the window", () => {
  it("opens on the overview and shows the server's version", async () => {
    sessionStorage.setItem("altiward.consoleToken", "console-token-000000001");
    const fetch = serve({});
    render(<App />);
    await screen.findByRole("link", { name: "Settings" });
    expect(await screen.findByText("Altiward 0.1.0")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
    await waitFor(() => expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/v1/overview"), expect.anything()));
  });
});

describe("signing in", () => {
  it("asks for a console token without single sign-on", async () => {
    serve({});
    render(<App />);
    await userEvent.type(await screen.findByLabelText("Console token"), "console-token-000000001");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Console token")).toBeInTheDocument(); // the sidebar's account
    expect(screen.getByText("Admin")).toBeInTheDocument();
    expect(sessionStorage.getItem("altiward.consoleToken")).toBe("console-token-000000001");
  });

  it("says when a token is wrong", async () => {
    serve({});
    render(<App />);
    await userEvent.type(await screen.findByLabelText("Console token"), "not-the-right-token");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The server rejected that token");
  });

  it("forgets the token when the server forbids it", async () => {
    serve({ tokenStatus: 403 });
    render(<App />);
    await userEvent.type(await screen.findByLabelText("Console token"), "console-token-000000001");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The server rejected that token");
    expect(sessionStorage.getItem("altiward.consoleToken")).toBeNull();
  });

  it("keeps the token and says to try again when the server can't sign it in", async () => {
    serve({ tokenStatus: 500 });
    render(<App />);
    await userEvent.type(await screen.findByLabelText("Console token"), "console-token-000000001");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Your token wasn’t rejected, so try again shortly");
    expect(alert).not.toHaveTextContent("rejected that token");
    expect(screen.getByLabelText("Console token")).toHaveValue("console-token-000000001");
    expect(sessionStorage.getItem("altiward.consoleToken")).toBeNull();
  });

  it("keeps a stored token when the server can't sign it in on reload", async () => {
    sessionStorage.setItem("altiward.consoleToken", "console-token-000000001");
    serve({ sso: true, tokenStatus: 500 });
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Your token wasn’t rejected, so try again shortly");
    expect(sessionStorage.getItem("altiward.consoleToken")).toBe("console-token-000000001");
    expect(screen.getByLabelText("Break-glass token")).toHaveValue("console-token-000000001");
  });

  it("offers single sign-on, with a break-glass token behind a link", async () => {
    window.history.replaceState(null, "", "/fleet");
    serve({ sso: true });
    render(<App />);
    const link = await screen.findByRole("link", { name: "Sign in with single sign-on" });
    expect(link).toHaveAttribute("href", "/v1/auth/login?next=%2Ffleet");
    expect(screen.getByRole("link", { name: "Use a different account" })).toHaveAttribute("href", "/v1/auth/login?select_account=1&next=%2Ffleet");
    expect(screen.queryByLabelText("Break-glass token")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Use a break-glass token instead" }));
    expect(screen.getByLabelText("Break-glass token")).toBeInTheDocument();
    expect(screen.getByText(/Each use is recorded/)).toBeInTheDocument();
  });

  it("explains why single sign-on sent the browser back", async () => {
    window.history.replaceState(null, "", "/?sso_error=no_role");
    serve({ sso: true });
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent("isn’t in a group that can use Altiward");
    expect(window.location.search).toBe("");
  });

  it("picks up the session cookie, shows who is signed in and signs out", async () => {
    const fetch = serve({ sso: true, session: { actor: "jane.doe@example.com", name: "Jane Doe", role: "operator", method: "sso", csrf_token: "c1" } });
    render(<App />);
    expect(await screen.findByText("Jane Doe")).toBeInTheDocument();
    expect(screen.getByText("Operator")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(await screen.findByRole("link", { name: "Sign in with single sign-on" })).toBeInTheDocument();
    const logout = fetch.mock.calls.find(([url]) => url === "/v1/auth/logout");
    expect(new Headers(logout?.[1]?.headers).get("X-CSRF-Token")).toBe("c1");
  });

  it("goes on to the identity provider when the server gives a sign-out address", async () => {
    const to = "https://login.microsoftonline.com/t/oauth2/v2.0/logout?client_id=app&post_logout_redirect_uri=https%3A%2F%2Faltiward.example.com%2Fsigned-out";
    serve({ sso: true, providerSignOutURL: to, session: { actor: "jane.doe@example.com", name: "Jane Doe", role: "operator", method: "sso", csrf_token: "c1" } });
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith(to));
    expect(await screen.findByRole("link", { name: "Sign in with single sign-on" })).toBeInTheDocument();
  });

  it("stays on the sign-in page after a local sign-out", async () => {
    serve({ sso: true, session: { actor: "jane.doe@example.com", name: "Jane Doe", role: "operator", method: "sso", csrf_token: "c1" } });
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    expect(await screen.findByRole("link", { name: "Sign in with single sign-on" })).toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();
  });

  it("shows the signed-out view when the identity provider sends the browser back to /signed-out", async () => {
    window.history.replaceState(null, "", "/signed-out");
    serve({ sso: true });
    render(<App />);
    const link = await screen.findByRole("link", { name: "Sign in with single sign-on" });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(link).toHaveAttribute("href", "/v1/auth/login?next=%2F"); // signing in again opens the overview
  });
});
