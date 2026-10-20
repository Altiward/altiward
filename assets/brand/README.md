# Brand assets

The SVGs here are Altiward's canonical brand sources (brand v2: graphite, warm paper and
one signal orange that means admin is held now).

| File | Use |
| --- | --- |
| `altiward-mark.svg` | The mark on light grounds: ink steps, orange top step |
| `altiward-mark-on-dark.svg` | The mark on graphite and other dark grounds: paper steps, orange top step |
| `altiward-mark-mono.svg` | One ink, for stamps and single-colour print |
| `altiward-avatar.svg` | The GitHub organisation's and other square profile pictures; the mark stays inside the inscribed circle, so circle crops keep it whole |
| `altiward-app-icon.svg` | The macOS app icon: graphite body, paper steps, orange top step |
| `altiward-app-icon-signal.svg` | The orange alternate, for the website and release notes only, never in the Dock |

Never rotate, outline, round, shadow or animate the mark.

## Generate images

From the repository root on macOS, run `make app-icon`. The renderers in
[`scripts/brand/`](../../scripts/brand/) generate these committed outputs:

| Output | Source |
| --- | --- |
| `agent/packaging/AppIcon.icns` | `altiward-app-icon.svg` |
| `agent/packaging/installer/background*.tiff` | Light and dark marks |
| `assets/brand/altiward-avatar.png` | `altiward-avatar.svg` |
| `docs/brand/social-altiward.png` | The repository text and the stair, in the console's fonts |

Commit changed outputs with their sources. Packaging uses the committed images and needs
no renderer. The social preview's colours follow the dark-theme tokens in
`console/src/styles.css`, and it loads the console's fonts, so run `make console-install`
once first.

## Export to consumers

The console serves copies of the two marks it uses. `make brand-sync` refreshes them and
`make brand-check` checks them; CI runs the check. Keep design-only variants here rather
than adding them to the console's public files.

Other repositories keep their own copies so each checkout is self-contained. Export to
an explicit destination from this repository's root:

```sh
scripts/brand/export.sh github ../.github
scripts/brand/export.sh website ../altiward.com
```

Append `--check` to compare without writing. The GitHub export includes the canonical
screenshot from `docs/images/console-overview.png`. The website keeps a separately
optimised screenshot and raster artwork; refresh those explicitly when the design changes.
The social-preview renderer accepts an explicit output path for a companion repository;
see its header. Upload social previews through the repository's GitHub settings.

The project licence grants no rights to the Altiward name or logo beyond describing the
origin of the software; see the root README's licence section.
