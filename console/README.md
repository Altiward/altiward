# Console

A React and TypeScript web app over the backend's API. It is laid out like a macOS app
(sidebar, toolbar, sortable tables, inspector, confirmation sheets) and dressed in the
Altiward brand v2: graphite and warm paper, and one signal orange that means "admin is
held right now".

| View | What it shows | API |
| --- | --- | --- |
| Overview | The first page: admins now by source and what needs a look, elevations over 7, 30 or 90 days, time held against time allowed, who elevates most, agent versions and SIEM delivery. Each term has a help tag, and each tile links to the filtered list behind it | `GET /v1/overview?days=` |
| Admins now | Everyone who holds admin rights, rights without a grant and overdue first | `GET /v1/sessions?open=true` |
| Sessions | Every elevation session, with its timeline and a revoke action | `GET /v1/sessions[/{id}]`, `POST /v1/sessions/{id}/revoke` |
| Fleet | Each Mac's versions, admin group, integrity checks and last check-in, in details that fold into sections; revoke one user or everyone but permanent admins. Retired Macs show under **Show › Retired**, with when their history is removed. With Intune connected, each Mac's primary user and last Intune check-in, and the Macs Intune manages that never reported | `GET /v1/devices`, `POST /v1/devices/{serial}/revoke`, `GET /v1/retention`, `GET /v1/mdm[/devices]` |
| Enrollments | Device keys; approve or reject keys waiting for approval, and revoke a key, which retires a Mac whose only key it is. With Intune connected, each key's Intune check, and **Not in Intune** on a Mac Intune doesn't list | `/v1/enrollments`, `GET /v1/mdm[/devices]` |
| Commands | Revokes sent to Macs and what each Mac did | `GET /v1/commands` |
| Activity | Every change made in the console, every sign-in, and what the server does by itself, such as removing old history | `GET /v1/audit` |
| Settings | **General**: enrolment approval, the alert for Macs that stop checking in, how long history is kept, and this browser's theme. **SIEM export**: each SIEM's queue with a test event and retry. **MDM**: the Intune connection and **Require an Intune match**. **Sign-ins** and **Updates** (admins): who is signed in, and newer releases | `/v1/settings`, `GET /v1/retention`, `/v1/exports`, `GET /v1/mdm`, `/v1/console-sessions`, `GET /v1/about` |

## Run it

```sh
make console-install   # once
make run-api           # terminal 1
make console-seed      # optional: demo Macs, sessions and an enrollment to approve
make console-dev       # terminal 2, then open http://localhost:5173
```

Sign in with a console token; `make run-api` uses `dev-console-token-001`. The token
stays in session storage for the tab. With single sign-on set up
the sign-in page leads with
**Sign in with single sign-on**, keeps the token as a break-glass option, and the
session lives in an HttpOnly cookie the console never sees. Changes send the CSRF token
from `GET /v1/auth/me`. The sidebar shows who is signed in and their role, and views
leave out what the role can't do (the server checks it as well).

In development Vite proxies `/v1` to the API on `127.0.0.1:8080`. In production the API
serves `console/dist` itself from the same origin: set `ALTIWARD_CONSOLE_DIR`, or build
the image (`make image`). `make run-api-console` runs it that way locally. Client routes
fall back to `index.html`, hashed assets are cached for good, and the pages carry a strict
same-origin Content-Security-Policy, so keep scripts and styles in files, not inline. The
image serves the third-party notices at `/third-party-notices.txt`, linked from Settings.

**Update check** ([`src/updates.ts`](src/updates.ts) for release data and caching,
[`src/useUpdateCheck.ts`](src/useUpdateCheck.ts) for the React hook): for admins only, the browser asks
`api.github.com` for the release list without cookies or a referrer, at most once a day
per admin's browser after a successful check and at most once an hour while GitHub can't
be reached, and Overview and Settings say when a newer server or agent is out. It runs only while
`GET /v1/about` reports `update_check` (`ALTIWARD_UPDATE_CHECK`, on by default), which is
also when the CSP's `connect-src` allows `https://api.github.com`.

## Design notes

- Brand tokens live in [`src/styles.css`](src/styles.css); components use the tokens,
  never raw values. Canonical logos live in [`assets/brand/`](../assets/brand/).
  [`public/brand/`](public/brand/) contains exported runtime copies; refresh them with
  `make brand-sync`.
- Type: Inter for reading, JetBrains Mono (`.data`) for serials, durations,
  fingerprints and UUIDs. Both are bundled from `@fontsource`, so the console makes no
  runtime calls to Google Fonts.
- States use the brand's StateBadge, always a word and a glyph: Elevated only for admin
  held now, Not granted for rights Privileges didn't grant, Ended for the past. Verified
  and Claimed describe the hook's claim.
- Sentence case everywhere; capitals only in labels (badges, column headings).
- Brand v4 tokens (Mono, the default) and the other themes (Slate, Moss and Paper) live in
  `styles.css` as one token block each, every colour given for light and dark with
  `light-dark()`. `theme.ts` keeps the person's choice in local storage and sets
  `data-theme` and `data-appearance` on `<html>`; a new theme needs every token and a line
  in `themes`. State tokens keep their meaning in every theme, and text tokens are 4.5:1 or
  better in light and dark.
- Selected rows and the sidebar's current item use `surface-300` with ink text. Buttons and
  nav counts use `action`, never a state colour. The gauge uses `elevated-ink`, because the
  `elevated` fill is too light to read as a thin bar.
- Increase Contrast (`prefers-contrast: more`) sets secondary text to ink and separators to
  the control border colour.
- Glyphs are 14px, 2px stroke, square caps; no shields, padlocks or keys.
- Destructive actions open a confirmation sheet with Cancel focused.

## Test

```sh
make console-test      # type-check + Vitest (jsdom, Testing Library)
```
