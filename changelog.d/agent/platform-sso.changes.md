- On a Mac registered for Platform SSO, events carry each person's UPN without a
  `UserPrincipalNames` entry (#27). The agent reads the account Platform SSO links to each
  Mac account from the Mac's local directory, keeps its own record of every link, and
  takes UPNs only from that record. Each change to a link, at any time, is sent as
  `agent.tamper`: `platform_sso_link_changed` when an account moves to another person's
  account, or is linked when it was last linked to someone else, another Mac account has
  the same link, or someone holds admin rights; `platform_sso_link` when a link is added
  otherwise (registering for Platform SSO adds one) or removed. A `UserPrincipalNames`
  entry still wins, but only one MDM sets: a map set outside MDM is now ignored, and fails
  the settings check.
- Every event of an elevation carries the same UPN: the one on record when its grant claim
  arrived, or when rights nobody granted were found, including none. So a link changed
  during the elevation can't move it onto someone else. The agent's store gains a column
  for this; an elevation open during the upgrade takes the UPN on record for each event.
- `PlatformSSOIdentity`, on by default, turns the Platform SSO read off when MDM sets it to
  `false`, for sites that allow only UPNs they supply. A value set outside MDM is ignored
  and fails the settings check. Turning it on again reports every link as added.
