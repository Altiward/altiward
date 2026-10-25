/** How to connect each SIEM, for the console to show and nothing more. SIEM settings live in
 *  the server's environment, so changing where events go needs the host or the Azure
 *  subscription, not a console session: the console never reads, stores or sends them.
 *  backend/internal/config's tests check the names here against the settings it reads. */

export type SiemSink = "splunk" | "sentinel" | "syslog";

export interface SiemSetting {
  name: string;
  /** What to put: a placeholder in angle brackets, or the default of an optional setting. */
  value: string;
  required: boolean;
  /** Kept as an app secret on Azure Container Apps rather than as a plain setting. */
  secret?: boolean;
  what: string;
}

export interface SiemGuide {
  sink: SiemSink;
  /** What to run or do first, before setting these. */
  intro: string;
  /** The guide, as a path in the repository with its anchor. */
  guide: string;
  settings: SiemSetting[];
}

/** Where the server runs: Docker Compose's .env, or Azure Container Apps' settings. */
export interface Where { azureApp?: string }

const splunk: SiemGuide = {
  sink: "splunk",
  intro: "Create an HTTP Event Collector token in Splunk for Altiward’s events.",
  guide: "integrations/splunk/README.md#setup",
  settings: [
    { name: "ALTIWARD_SPLUNK_HEC_URL", value: "https://<your Splunk>:8088", required: true, what: "Splunk’s HTTP Event Collector address, without a path" },
    { name: "ALTIWARD_SPLUNK_HEC_TOKEN", value: "<the HEC token>", required: true, secret: true, what: "The HTTP Event Collector token" },
    { name: "ALTIWARD_SPLUNK_INDEX", value: "<an index>", required: false, what: "The index to write to. Unset, the token’s default index" },
  ],
};

const sentinelOptional: SiemSetting[] = [
  { name: "ALTIWARD_SENTINEL_STREAM", value: "Custom-AltiwardOCSF", required: false, what: "The rule’s stream" },
];

const sentinel: SiemGuide = {
  sink: "sentinel",
  intro: "Run integrations/sentinel/setup.sh against your Sentinel workspace. It creates the table, the data collection rule and an app, and prints these settings.",
  guide: "integrations/sentinel/README.md#setup",
  settings: [
    { name: "ALTIWARD_SENTINEL_ENDPOINT", value: "<the logs ingestion URL>", required: true, what: "Where events are sent" },
    { name: "ALTIWARD_SENTINEL_DCR_ID", value: "<the rule's immutable ID>", required: true, what: "The data collection rule" },
    { name: "ALTIWARD_SENTINEL_TENANT_ID", value: "<your directory ID>", required: true, what: "The app’s directory" },
    { name: "ALTIWARD_SENTINEL_CLIENT_ID", value: "<the app's client ID>", required: true, what: "The app the server signs in as" },
    { name: "ALTIWARD_SENTINEL_CLIENT_SECRET", value: "<the app's secret>", required: true, secret: true, what: "The app’s secret" },
    ...sentinelOptional,
    { name: "ALTIWARD_SENTINEL_AUTH", value: "secret", required: false, what: "Set it to certificate to sign in with a certificate instead of a secret, or to managed-identity on an Azure VM" },
    { name: "ALTIWARD_SENTINEL_CERTIFICATE_FILE", value: "<the certificate and key's PEM file>", required: false, what: "With certificate only, in place of the secret" },
  ],
};

/** On Azure Container Apps the server signs in as the app's managed identity: no secret. */
const sentinelOnAzure: SiemGuide = {
  sink: "sentinel",
  intro: "Run integrations/sentinel/setup.sh with --identity and the deployment’s identityClientId output. It grants the app’s managed identity access and prints these settings: no secret needed.",
  guide: "integrations/sentinel/README.md#on-azure-container-apps-no-secret",
  settings: [
    { name: "ALTIWARD_SENTINEL_ENDPOINT", value: "<the logs ingestion URL>", required: true, what: "Where events are sent" },
    { name: "ALTIWARD_SENTINEL_DCR_ID", value: "<the rule's immutable ID>", required: true, what: "The data collection rule" },
    { name: "ALTIWARD_SENTINEL_AUTH", value: "managed-identity", required: true, what: "Sign in as the app’s managed identity" },
    { name: "ALTIWARD_SENTINEL_CLIENT_ID", value: "<identityClientId>", required: true, what: "The managed identity’s client ID" },
    ...sentinelOptional,
  ],
};

const syslog: SiemGuide = {
  sink: "syslog",
  intro: "For QRadar, ArcSight, Elastic and others: open a syslog listener, over TLS unless it’s on a network you trust.",
  guide: "integrations/syslog/README.md#setup",
  settings: [
    { name: "ALTIWARD_SYSLOG_ADDR", value: "<host>:6514", required: true, what: "The listener, as host:port" },
    { name: "ALTIWARD_SYSLOG_TLS", value: "true", required: false, what: "Set it to false for plain TCP, only on a network you trust" },
    { name: "ALTIWARD_SYSLOG_CA_FILE", value: "<a PEM file>", required: false, what: "Trust only this CA for the listener’s certificate" },
    { name: "ALTIWARD_SYSLOG_FORMAT", value: "cef", required: false, what: "cef, or json for the OCSF record" },
    { name: "ALTIWARD_SYSLOG_FRAMING", value: "octet", required: false, what: "octet (a length prefix, RFC 6587), or newline for listeners that read lines" },
  ],
};

/** How to connect each SIEM, for where the server runs. */
export function siemGuides(where: Where): SiemGuide[] {
  return [splunk, where.azureApp !== undefined ? sentinelOnAzure : sentinel, syslog];
}

/** The app secret's name for a setting on Azure: ALTIWARD_SPLUNK_HEC_TOKEN → splunk-hec-token. */
export function secretName(setting: string): string {
  return setting.replace(/^ALTIWARD_/, "").toLowerCase().replaceAll("_", "-");
}

/** What to copy: .env lines, with the optional settings commented out at their defaults, or on
 *  Azure Container Apps the commands that set the required ones, secrets as app secrets. */
export function siemSnippet(guide: SiemGuide, where: Where): string {
  if (where.azureApp === undefined) {
    return guide.settings.map((s) => `${s.required ? "" : "# "}${s.name}=${s.value}`).join("\n");
  }
  const app = `--name ${where.azureApp || "<the app>"} --resource-group <its resource group>`;
  const required = guide.settings.filter((s) => s.required);
  const secrets = required.filter((s) => s.secret);
  const lines: string[] = [];
  if (secrets.length > 0) {
    lines.push(`az containerapp secret set ${app} \\\n  --secrets ${secrets.map((s) => `${secretName(s.name)}=${s.value}`).join(" ")}`);
  }
  const vars = required.map((s) => `${s.name}=${s.secret ? `secretref:${secretName(s.name)}` : s.value}`);
  lines.push(`az containerapp update ${app} --container-name altiward \\\n  --set-env-vars ${vars.join(" \\\n  ")}`);
  return lines.join("\n");
}
