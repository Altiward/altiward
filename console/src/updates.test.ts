import { afterEach, describe, expect, it, vi } from "vitest";
import { githubFetch, notes, release, releases } from "./test/fixtures";
import {
  RELEASES_URL, available, checkReleases, compareVersions, dismiss, forgetMemory, hasSecurityFix, isDismissed, isVersion,
  latestRelease,
} from "./updates";

describe("compareVersions", () => {
  it("orders like upgrade.sh: a pre-release before its release", () => {
    expect(compareVersions("0.3.0-rc.1", "0.3.0-rc.2")).toBe(-1);
    expect(compareVersions("0.3.0-rc.2", "0.3.0")).toBe(-1);
    expect(compareVersions("0.3.0", "0.3.0-rc.1")).toBe(1);
    expect(compareVersions("0.2.0", "0.1.0")).toBe(1);
    expect(compareVersions("0.1.0", "0.2.0")).toBe(-1);
    expect(compareVersions("0.1.0", "0.1.0")).toBe(0);
    expect(compareVersions("0.10.0", "0.9.9")).toBe(1);
    expect(compareVersions("1.0.0", "0.99.99")).toBe(1);
    expect(compareVersions("0.3.0-rc.10", "0.3.0-rc.9")).toBe(1);
    expect(compareVersions("0.3.0-rc.1", "0.3.0-rc.1.1")).toBe(-1); // fewer parts sort first
    expect(compareVersions("0.3.0-1", "0.3.0-rc")).toBe(-1); // numbers sort before words
    expect(compareVersions("0.3.0+build.5", "0.3.0")).toBe(0); // build metadata is ignored
  });

  it("counts a version that isn't X.Y.Z as 0.0.0", () => {
    expect(compareVersions("dev", "0.0.1")).toBe(-1);
    expect(compareVersions("dev", "0.0.0")).toBe(0);
  });

  it("knows what a version is", () => {
    for (const v of ["0.1.0", "0.3.0-rc.1", "12.0.4"]) expect(isVersion(v)).toBe(true);
    for (const v of ["dev", "", "0.1", "v0.1.0", "0.1.0.1", "latest"]) expect(isVersion(v)).toBe(false);
  });
});

describe("latestRelease", () => {
  it("picks the newest server and agent from one mixed list, skipping drafts and pre-releases", () => {
    expect(latestRelease(releases(), "server", { prereleases: false })).toEqual({
      version: "0.2.0", url: "https://github.com/Altiward/altiward/releases/tag/server-v0.2.0", security: true, packageUrl: null,
    });
    expect(latestRelease(releases(), "agent", { prereleases: false })).toEqual({
      version: "0.2.0", url: "https://github.com/Altiward/altiward/releases/tag/agent-v0.2.0", security: false,
      packageUrl: "https://github.com/Altiward/altiward/releases/download/agent-v0.2.0/Altiward-0.2.0.pkg",
    });
  });

  it("includes release candidates when asked, never drafts", () => {
    expect(latestRelease(releases(), "server", { prereleases: true })?.version).toBe("0.3.0-rc.1");
  });

  it("doesn't trust the list's order", () => {
    const list = [release("server-v0.1.0"), release("server-v0.10.0"), release("server-v0.9.0")];
    expect(latestRelease(list, "server", { prereleases: false })?.version).toBe("0.10.0");
  });

  it("skips a pre-release GitHub marks as one even without -rc in its tag", () => {
    const list = [release("server-v0.3.0", { prerelease: true }), release("server-v0.2.0")];
    expect(latestRelease(list, "server", { prereleases: false })?.version).toBe("0.2.0");
  });

  it("ignores tags that aren't a release of that product", () => {
    const list = [release("server-vnext"), release("forwarder-v9.0.0"), release("agent-v0.1.0")];
    expect(latestRelease(list, "server", { prereleases: false })).toBeNull();
  });
});

describe("available", () => {
  it("offers a newer server and agent", () => {
    const a = available("0.1.0", ["0.1.0", "0.1.2"], releases());
    expect(a.newerServer?.version).toBe("0.2.0");
    expect(a.newerAgent?.version).toBe("0.2.0");
  });

  it("offers nothing when up to date", () => {
    const a = available("0.2.0", ["0.2.0"], releases());
    expect(a.server?.version).toBe("0.2.0");
    expect(a.newerServer).toBeNull();
    expect(a.newerAgent).toBeNull();
  });

  it("offers release candidates only to a server running one", () => {
    expect(available("0.2.0", [], releases()).newerServer).toBeNull();
    expect(available("0.2.1-rc.1", [], releases()).newerServer?.version).toBe("0.3.0-rc.1");
  });

  it("gives no notice for a dev build", () => {
    const a = available("dev", [], releases());
    expect(a.server?.version).toBe("0.2.0");
    expect(a.newerServer).toBeNull();
  });

  it("offers an agent only when the newest in the fleet is older", () => {
    expect(available("0.2.0", [], releases()).newerAgent).toBeNull();
    expect(available("0.2.0", ["0.1.0", "0.2.0"], releases()).newerAgent).toBeNull();
    expect(available("0.2.0", ["", "unknown"], releases()).newerAgent).toBeNull();
  });
});

describe("hasSecurityFix", () => {
  it("reads the Security section", () => {
    expect(hasSecurityFix(notes())).toBe(false);
    expect(hasSecurityFix(notes({ security: "- Fixes a session fixation." }))).toBe(true);
    expect(hasSecurityFix(notes({ security: "none" }))).toBe(false);
    expect(hasSecurityFix(notes({ security: "" }))).toBe(false);
    expect(hasSecurityFix("### Security\r\n\r\nNone.\r\n\r\n### Changes\r\n\r\n- x\r\n")).toBe(false);
    expect(hasSecurityFix("### Security\n- Fixes a session fixation.")).toBe(true); // the last section
    expect(hasSecurityFix("### Changes\n- Security headers on more pages.")).toBe(false);
    expect(hasSecurityFix(null)).toBe(false);
  });
});

describe("checkReleases", () => {
  const day = 24 * 60 * 60 * 1000;
  const t0 = Date.parse("2026-11-02T12:00:00Z");

  it("asks GitHub without cookies or a referrer, and caches the answer for a day", async () => {
    const fetch = githubFetch();
    const first = await checkReleases(t0);
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0];
    expect(url).toBe(RELEASES_URL);
    expect(RELEASES_URL).toBe("https://api.github.com/repos/Altiward/altiward/releases?per_page=50");
    expect(init).toMatchObject({ credentials: "omit", referrerPolicy: "no-referrer" });
    expect(first.failed).toBe(false);
    expect(first.checkedAt).toBe(new Date(t0).toISOString());
    expect(first.releases?.map((r) => r.tag_name)).toContain("server-v0.2.0");

    const cached = await checkReleases(t0 + day - 1);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(cached.checkedAt).toBe(first.checkedAt);

    await checkReleases(t0 + day + 1);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("fails quietly, keeping when it last worked", async () => {
    githubFetch();
    await checkReleases(t0);
    githubFetch("offline");
    const failed = await checkReleases(t0 + 2 * day);
    expect(failed).toEqual({ releases: null, checkedAt: new Date(t0).toISOString(), failed: true });
    githubFetch(403);
    expect((await checkReleases(t0 + 3 * day)).failed).toBe(true);
  });

  it("treats an answer that isn't a release list as a failure", async () => {
    const fetch = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    expect(await checkReleases(t0)).toEqual({ releases: null, checkedAt: null, failed: true });
  });

  describe("without storage", () => {
    const block = () => {
      vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("blocked"); });
      vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("blocked"); });
    };
    afterEach(() => {
      vi.restoreAllMocks();
      forgetMemory();
    });

    it("still checks, and keeps the answer in memory for the tab", async () => {
      const fetch = githubFetch();
      block();
      const first = await checkReleases(t0);
      expect(first.releases).not.toBeNull();
      // Another mount of Overview or Settings in the same tab asks GitHub nothing.
      expect(await checkReleases(t0 + 60_000)).toEqual(first);
      expect(fetch).toHaveBeenCalledTimes(1);
      await checkReleases(t0 + day + 1);
      expect(fetch).toHaveBeenCalledTimes(2);
    });

    it("waits an hour after a failure, as with storage", async () => {
      const fetch = githubFetch("offline");
      block();
      expect((await checkReleases(t0)).failed).toBe(true);
      expect((await checkReleases(t0 + 59 * 60_000)).failed).toBe(true);
      expect(fetch).toHaveBeenCalledTimes(1);
      await checkReleases(t0 + 61 * 60_000);
      expect(fetch).toHaveBeenCalledTimes(2);
    });

    it("remembers a dismissal for the tab", () => {
      block();
      dismiss("server", "0.2.0");
      expect(isDismissed("server", "0.2.0")).toBe(true);
      expect(isDismissed("server", "0.3.0")).toBe(false);
    });
  });

  describe("for a server newer than every server release listed", () => {
    const before = [release("server-v0.1.1"), release("server-v0.2.0-rc.2"), release("agent-v0.1.0")];

    it("asks again within the day, at most once an hour, until the list has it", async () => {
      const fetch = githubFetch(before);
      await checkReleases(t0, { running: "0.2.0" });
      await checkReleases(t0 + 59 * 60_000, { running: "0.2.0" });
      expect(fetch).toHaveBeenCalledTimes(1);
      await checkReleases(t0 + 61 * 60_000, { running: "0.2.0" });
      expect(fetch).toHaveBeenCalledTimes(2);

      const after = githubFetch([release("server-v0.2.0"), ...before]);
      const check = await checkReleases(t0 + 3 * 60 * 60_000, { running: "0.2.0" });
      expect(check.releases?.map((r) => r.tag_name)).toContain("server-v0.2.0");
      await checkReleases(t0 + 5 * 60 * 60_000, { running: "0.2.0" });
      expect(after).toHaveBeenCalledTimes(1);
    });

    it("doesn't ask again for a server the list has, an older one or a dev build", async () => {
      const fetch = githubFetch(before);
      await checkReleases(t0);
      for (const running of ["0.1.1", "0.1.0", "0.2.0-rc.2", "dev"]) await checkReleases(t0 + 2 * 60 * 60_000, { running });
      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it("keeps the list it has when asking again fails", async () => {
      githubFetch(before);
      const first = await checkReleases(t0);
      const fetch = githubFetch("offline");
      expect(await checkReleases(t0 + 2 * 60 * 60_000, { running: "0.2.0" })).toEqual(first);
      expect(await checkReleases(t0 + 2 * 60 * 60_000 + 30 * 60_000, { running: "0.2.0" })).toEqual(first);
      expect(fetch).toHaveBeenCalledTimes(1);
    });
  });

  it("asks again an hour after a failure, not sooner", async () => {
    const fetch = githubFetch("offline");
    await checkReleases(t0);
    await checkReleases(t0 + 59 * 60_000);
    expect(fetch).toHaveBeenCalledTimes(1);
    await checkReleases(t0 + 61 * 60_000);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});

describe("dismissing", () => {
  it("hides a notice for that version only", () => {
    expect(isDismissed("server", "0.2.0")).toBe(false);
    dismiss("server", "0.2.0");
    expect(isDismissed("server", "0.2.0")).toBe(true);
    expect(isDismissed("server", "0.3.0")).toBe(false);
    expect(isDismissed("agent", "0.2.0")).toBe(false);
  });
});
