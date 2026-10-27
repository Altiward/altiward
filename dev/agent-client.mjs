// The agent's side of the protocol, for scripts that stand in for Macs: each fake Mac
// enrolls with its own P-256 key and signs its requests as the agent does. seed.mjs and
// scripts/agent-smoke.mjs use it. Node's built-in modules only.
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";

/** A fake Mac's hardware UUID: the same for a serial every time, so enrolling it again with
 *  a new key looks like a reinstall on the same hardware, not a different Mac. */
export function hardwareUUID(serial) {
  const h = createHash("sha256").update(`altiward-dev-hardware:${serial}`).digest("hex").toUpperCase();
  return [h.slice(0, 8), h.slice(8, 12), h.slice(12, 16), h.slice(16, 20), h.slice(20, 32)].join("-");
}

/** A client for one server. enrollToken is an agent token, without the organisation. */
export function agentClient(server, enrollToken) {
  /** One request: with bearer, a console or agent token; with mac, signed as that Mac. */
  async function request(method, path, { bearer, body, mac } = {}) {
    const raw = body === undefined ? "" : JSON.stringify(body);
    const headers = { "Content-Type": "application/json" };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    if (mac) {
      const ts = Math.floor(Date.now() / 1000);
      const digest = createHash("sha256").update(raw).digest("hex");
      const canonical = ["ALTIWARD-SIG-V1", method, path, ts, digest].join("\n");
      headers.Authorization = `AltiwardDevice ${mac.deviceID}`;
      headers["X-Altiward-Timestamp"] = String(ts);
      headers["X-Altiward-Signature"] = sign("sha256", Buffer.from(canonical), { key: mac.privateKey, dsaEncoding: "der" }).toString("base64");
    }
    const res = await fetch(server + path, { method, headers, body: raw || undefined });
    const text = await res.text();
    if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text}`);
    return text ? JSON.parse(text) : {};
  }

  /** Enrolls a fake Mac with a new key: { serial, deviceID, status, privateKey }.
   *  `keyStorage` is where the Mac says its key is kept; null leaves it out. */
  async function enroll(serial, { keyStorage = "secure_enclave" } = {}) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const spki = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const body = { serial, hardware_uuid: hardwareUUID(serial), public_key: spki };
    if (keyStorage) body.key_storage = keyStorage;
    const r = await request("POST", "/v1/agent/enroll", { bearer: enrollToken, body });
    return { serial, deviceID: r.device_id, status: r.status, privateKey };
  }

  /** Replaces mac's key with a new one, as agent 1.0 does: the old key signs the request and
   *  the new one signs a proof that it is held (docs/schema/rotation-vector.json). The new
   *  key is kept where `keyStorage` says, a file by default, and mac then holds it. The
   *  server refuses a key active for less than 24 hours. */
  async function rotate(mac, { keyStorage = "software" } = {}) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const spki = publicKey.export({ type: "spki", format: "der" });
    const statement = ["ALTIWARD-ROTATE-V1", mac.deviceID, createHash("sha256").update(spki).digest("hex")].join("\n");
    const proof = sign("sha256", Buffer.from(statement), { key: privateKey, dsaEncoding: "der" }).toString("base64");
    const r = await request("POST", "/v1/agent/rotate", { mac, body: { public_key: spki.toString("base64"), key_storage: keyStorage, proof } });
    return Object.assign(mac, { deviceID: r.device_id, status: r.status, privateKey });
  }

  return { request, enroll, rotate };
}

/** An event from mac, as the agent sends it (docs/schema/event.schema.json). */
export function event(mac, type, at, { user, session, elevation, detail = {} } = {}) {
  return {
    schema_version: 1, event_id: randomUUID(), type, session_id: session ?? null, timestamp: at,
    device: { serial: mac.serial, hardware_uuid: hardwareUUID(mac.serial), os_version: "26.1.0", agent_version: mac.agentVersion ?? "1.0.0", privileges_version: "2.6.0" },
    user: user ? { local_name: user[0], upn: user[1] ?? null } : null,
    elevation: elevation ?? null, delayed: false, detail,
  };
}
