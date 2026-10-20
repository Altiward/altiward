import { describe, expect, it, vi } from "vitest";
import { ApiError, can, createApi, probeSignIn } from "./api";

function fakeFetch(status: number, body: unknown) {
  return vi.fn(async (_url: string, _init?: RequestInit) =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
  );
}

describe("api client", () => {
  it("sends the console token and builds queries", async () => {
    const fetch = fakeFetch(200, { sessions: [] });
    const api = createApi({ token: "console-token-0001" }, { fetch });
    await api.sessions({ open: true, user: "j doe" });
    const [url, init] = fetch.mock.calls[0];
    expect(url).toBe("/v1/sessions?open=true&user=j+doe");
    expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer console-token-0001");
  });

  it("posts JSON bodies", async () => {
    const fetch = fakeFetch(201, { command_id: "c1", status: "pending" });
    const api = createApi({ token: "t" }, { fetch });
    const cmd = await api.revokeDevice("C02X", "jdoe");
    const [url, init] = fetch.mock.calls[0];
    expect(url).toBe("/v1/devices/C02X/revoke");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ user: "jdoe" });
    expect(cmd.command_id).toBe("c1");
  });

  it("raises the server's error message", async () => {
    const api = createApi({ token: "t" }, { fetch: fakeFetch(409, { error: "session has already ended" }) });
    await expect(api.revokeSession("s1")).rejects.toEqual(new ApiError(409, "session has already ended"));
  });

  it("signs out on 401", async () => {
    const onUnauthorized = vi.fn();
    const api = createApi({ token: "t" }, { fetch: fakeFetch(401, { error: "missing or invalid bearer token" }), onUnauthorized });
    await expect(api.devices()).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("relies on the session cookie and sends the CSRF token with changes", async () => {
    const fetch = fakeFetch(200, { devices: [] });
    const api = createApi({ csrf: "csrf-1" }, { fetch });
    await api.devices();
    let headers = new Headers(fetch.mock.calls[0][1]?.headers);
    expect(headers.get("Authorization")).toBeNull();
    expect(headers.get("X-CSRF-Token")).toBeNull();
    await api.revokeDevice("C02X");
    headers = new Headers(fetch.mock.calls[1][1]?.headers);
    expect(headers.get("X-CSRF-Token")).toBe("csrf-1");
  });

  it("signs out with no response body", async () => {
    const fetch = vi.fn(async () => new Response(null, { status: 204 }));
    await expect(createApi({ csrf: "c" }, { fetch }).signOut()).resolves.toBeUndefined();
    expect(fetch).toHaveBeenCalledWith("/v1/auth/logout", expect.objectContaining({ method: "POST" }));
  });

  it("explains an unreachable server", async () => {
    const api = createApi({ token: "t" }, { fetch: vi.fn(async () => { throw new TypeError("Failed to fetch"); }) });
    await expect(api.devices()).rejects.toEqual(new ApiError(0, "Can’t reach the Altiward server. Check your connection, then try again."));
  });
});

describe("signing in", () => {
  it("finds the session cookie's person when single sign-on is on", async () => {
    const me = { actor: "jane@example.com", name: "Jane", role: "operator", method: "sso", csrf_token: "c" };
    const fetch = vi.fn(async (url: string) => new Response(JSON.stringify(url === "/v1/auth/config" ? { sso: true } : me), { status: 200 }));
    expect(await probeSignIn(fetch)).toEqual({ sso: true, me });
  });

  it("asks for nothing more without single sign-on, or from an older server", async () => {
    const off = vi.fn(async () => new Response(JSON.stringify({ sso: false }), { status: 200 }));
    expect(await probeSignIn(off)).toEqual({ sso: false, me: null });
    expect(off).toHaveBeenCalledOnce();
    const old = vi.fn(async () => new Response("{}", { status: 404 }));
    expect(await probeSignIn(old)).toEqual({ sso: false, me: null });
  });

  it("orders roles", () => {
    expect(can("admin", "operator")).toBe(true);
    expect(can("operator", "operator")).toBe(true);
    expect(can("viewer", "operator")).toBe(false);
    expect(can(undefined, "viewer")).toBe(false);
  });
});
