import { describe, expect, it } from "vitest";
import { bySerial, normaliseSerial } from "./mdm";
import { mdmDevice } from "./test/fixtures";

describe("normaliseSerial", () => {
  it("trims and upper-cases, as the server matches serials", () => {
    expect(normaliseSerial("  c02xk0aajgh5 ")).toBe("C02XK0AAJGH5");
    expect(normaliseSerial("C02XK0AAJGH5")).toBe("C02XK0AAJGH5");
  });
});

describe("bySerial", () => {
  it("finds a device whatever the case or spacing of its serial", () => {
    const map = bySerial([mdmDevice({ serial: " c02xk0aajgh5", name: "Jane's Mac" })]);
    expect(map.get(normaliseSerial("C02XK0AAJGH5"))?.name).toBe("Jane's Mac");
  });

  it("keeps the record with the newest check-in when Intune lists a serial twice", () => {
    const old = mdmDevice({ name: "Old", last_check_in: "2026-10-01T00:00:00Z" });
    const fresh = mdmDevice({ name: "New", last_check_in: "2026-10-17T00:00:00Z" });
    expect(bySerial([old, fresh]).get("C02XK0AAJGH5")?.name).toBe("New");
    expect(bySerial([fresh, old]).get("C02XK0AAJGH5")?.name).toBe("New");
  });

  it("prefers a record that has checked in over one that never has", () => {
    const never = mdmDevice({ name: "Never", last_check_in: undefined });
    const seen = mdmDevice({ name: "Seen", last_check_in: "2020-01-01T00:00:00Z" });
    expect(bySerial([seen, never]).get("C02XK0AAJGH5")?.name).toBe("Seen");
    expect(bySerial([never, seen]).get("C02XK0AAJGH5")?.name).toBe("Seen");
  });
});
