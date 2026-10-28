- On a Mac registered for Platform SSO, events carry each person's UPN without a
  `UserPrincipalNames` entry (#27): the agent reads the Entra ID account Platform SSO links
  to each Mac account from the Mac's local directory. A `UserPrincipalNames` entry still
  wins, but only one MDM sets: a map set outside MDM now fails the settings check, and the
  link wins over it. A session keeps the UPN its user had when the grant arrived, so every
  event of the session carries the same one. The persistence snapshot includes each
  account's link, so one added, changed or removed while someone holds admin rights is
  reported on their session as a changed account, with the new link in `platform_sso`.
  The agent's store gains a column for this; a session open during the upgrade reads the
  UPN for each event as before, and may report a changed account once if its Mac has a link.
