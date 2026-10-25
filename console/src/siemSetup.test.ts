import { describe, expect, it } from "vitest";
import { secretName, siemGuides, siemSnippet } from "./siemSetup";

describe("SIEM setup help", () => {
  // backend/internal/config checks the names against the settings the server reads.
  it("gives .env lines, with optional settings commented out at their defaults", () => {
    const [splunk] = siemGuides({});
    expect(siemSnippet(splunk, {})).toBe(
      "ALTIWARD_SPLUNK_HEC_URL=https://<your Splunk>:8088\n" +
        "ALTIWARD_SPLUNK_HEC_TOKEN=<the HEC token>\n" +
        "# ALTIWARD_SPLUNK_INDEX=<an index>");
  });

  it("on Azure Container Apps, gives the commands, with secrets kept as app secrets", () => {
    const [splunk] = siemGuides({ azureApp: "altiward-app" });
    expect(siemSnippet(splunk, { azureApp: "altiward-app" })).toBe(
      "az containerapp secret set --name altiward-app --resource-group <its resource group> \\\n" +
        "  --secrets splunk-hec-token=<the HEC token>\n" +
        "az containerapp update --name altiward-app --resource-group <its resource group> --container-name altiward \\\n" +
        "  --set-env-vars ALTIWARD_SPLUNK_HEC_URL=https://<your Splunk>:8088 \\\n" +
        "  ALTIWARD_SPLUNK_HEC_TOKEN=secretref:splunk-hec-token");
    expect(secretName("ALTIWARD_SENTINEL_CLIENT_SECRET")).toBe("sentinel-client-secret");
  });

  it("on Azure Container Apps, has Sentinel sign in as the app's managed identity, with no secret", () => {
    const sentinel = siemGuides({ azureApp: "" }).find((g) => g.sink === "sentinel")!;
    const snippet = siemSnippet(sentinel, { azureApp: "" });
    expect(snippet).toContain("ALTIWARD_SENTINEL_AUTH=managed-identity");
    expect(snippet).not.toContain("secret set");
    expect(snippet).toContain("--name <the app>");
    expect(sentinel.guide).toBe("integrations/sentinel/README.md#on-azure-container-apps-no-secret");
  });

  it("holds placeholders and defaults, never a value from the server", () => {
    for (const where of [{}, { azureApp: "a" }]) {
      for (const g of siemGuides(where)) {
        for (const s of g.settings.filter((s) => s.required && s.name !== "ALTIWARD_SENTINEL_AUTH")) {
          expect(s.value).toMatch(/<[^>]+>/);
        }
      }
    }
  });
});
