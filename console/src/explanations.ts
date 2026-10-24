// Plain-words explanations for terms the console uses, shown in Explain help tags and as
// hover hints in table rows. Keep them to a sentence or two, and true for every deployment.

import type { State } from "./format";

export const explanations = {
  adminsNow:
    "People holding admin rights on an enrolled Mac right now. Permanent admins, who always keep their rights, aren’t counted.",
  privileges: "Rights granted through SAP Privileges and reported to Altiward by its hook.",
  withoutGrant:
    "Admin rights that nobody granted through Privileges: someone was added to the admin group directly, " +
    "or an account was created as an admin. Each one is a finding in your SIEM. " +
    "From agent 0.2.0, Macs whose profile sets OutOfBandEnforcement to enforce remove them after a grace period.",
  needsALook: "Things that need someone to look at them now. Each one clears by itself once it’s fixed.",
  pastExpiry:
    "Someone still holds admin rights after their allowed time ran out, usually because Privileges’ timer was stopped.",
  failingChecks:
    "The agent found a change to something that protects it, such as its LaunchDaemon, its app signature, " +
    "its settings or Privileges’ settings.",
  notCheckingIn:
    "The agent hasn’t checked in for longer than Settings allows (72 hours by default). The Mac may be off or " +
    "offline, or Altiward may have been removed.",
  elevations: "Each time someone got admin rights. Extending rights doesn’t count as a new elevation.",
  median:
    "The middle value: half of the elevations that ended were shorter, half longer. The time allowed is what was " +
    "set when the rights were granted.",
  givenBackEarly: "Ended at least a minute before the rights would have expired.",
  agentVersions:
    "An unsupported agent is older than the oldest release this server supports. Update it with the latest package.",
  keyStorage:
    "Where the Mac said its key is kept when it enrolled; Altiward can’t check it. A key in the Secure Enclave " +
    "can’t be copied off the Mac. A key in a file can be copied by someone with admin rights on the Mac. " +
    "Agents before 0.2.0 don’t say, and keep their key in a file.",
  siemState:
    "Delivering: keeping up. Behind: events have waited more than 15 minutes. Failing: sending failed, and " +
    "Settings shows the error. Nothing sent yet: no events since the SIEM was set up.",
} as const;

/** What each session state badge means. */
export const stateTips: Record<State, string> = {
  elevated: "Admin rights are held now, granted through Privileges.",
  verified: "Altiward’s daemon checked the admin group itself and it matched what was reported.",
  claimed:
    "What was reported didn’t match the admin group when Altiward’s daemon checked it, so treat it as unconfirmed.",
  "not-granted": explanations.withoutGrant,
  ended: "The admin rights have been removed or given back.",
};

/** Where a session's rights came from. */
export const sourceTips: Record<string, string> = {
  privileges: explanations.privileges,
  out_of_band: explanations.withoutGrant,
};

/** What each session flag means, by flag code. */
export const flagTips: Record<string, string> = {
  unverified_claim: "Privileges’ hook reported a change that didn’t match the admin group when Altiward’s daemon checked it.",
  orphan_revoke:
    "Altiward saw the rights removed without seeing them granted, for example when the agent was installed while " +
    "someone was already an admin.",
  out_of_band: explanations.withoutGrant,
  overdue: "The rights outlived their expiry and the grace period after it.",
  after_out_of_band:
    "This grant replaced admin rights nobody granted. Privileges’ hook reported it, and the user can run the hook " +
    "by hand, so check the grant is real.",
  persistence_detected:
    "Something that could keep access after the rights end appeared during this window, such as a launch item, " +
    "sudoers rule, SSH key, local account or remote access setting.",
};

/** What each integrity check confirms when it passes, by check code. */
export const checkTips: Record<string, string> = {
  launch_daemon: "The LaunchDaemon that keeps Altiward’s agent running is present and unchanged.",
  code_signature: "Altiward’s app still carries a valid signature from its developer, so nothing in it was changed.",
  settings_managed:
    "Altiward’s server, permanent admins, expiry enforcement and hook requirement settings come from a configuration profile, not a local file that someone with admin rights could edit.",
  privileges_tamper_protection: "SAP Privileges’ own tamper protection is on.",
  privileges_hook: "Privileges is still set to run Altiward's hook, and its checksum matches, so Privileges reports each change of admin rights.",
  privileges_timer: "Privileges’ timer, which removes admin rights when they expire, is running while someone holds them.",
  agent_version: "The agent hasn’t been replaced with an older release.",
};

export const persistenceCheckTip =
  "After each grant and end, and at each check-in, the agent looks for new launch items, sudoers rules, SSH keys, " +
  "local accounts and remote access, and reports what changed. It can only report places it can read.";
