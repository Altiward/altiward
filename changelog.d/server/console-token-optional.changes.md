- `ALTIWARD_CONSOLE_TOKENS` may be empty in `compose.yaml`, which turns the break-glass
  login off once single sign-on works. The server refuses to start with no console token
  and no single sign-on, or with no console token and no `ALTIWARD_OIDC_ADMIN_GROUPS`,
  because nobody could then sign in, or approve Macs and change settings. A server with
  several organisations checks each one: each needs a console token of its own, or single
  sign-on serving it (`ALTIWARD_OIDC_TENANT`) with admin groups.
- The install guide has one section on the console token, "Console token and
  break-glass": creating one, where to keep it, what's recorded, changing it without a
  gap, revoking one or a leaked one, and turning it off, with Docker Compose and on Azure.
