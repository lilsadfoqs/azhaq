AZHAQ / INTERFACE GLYPHS

32 original vector glyphs, drawn on a 32-unit grid.
Stroke: 1.9 units. Square terminals and chamfered corners follow the logo.
Recommended UI sizes: 22, 24 and 32 px. Touch targets: at least 44 x 44 px.
Use one colour. Keep text or an accessible name for every actionable icon.
Do not use the decorative illustrations as evidence of real scan output.

Contents
- Named SVG masters: inherit currentColor when inlined.
- sprite.svg: symbols named az-map, az-docs, az-roles, etc.
- Named light/dark PNG exports: 64 x 64, transparent.
- icon-sheet.svg/png: the complete set at display and interface sizes.
- access/agent/export-module.svg/png: decorative module illustrations.
- workspace-network.svg/png: desktop conceptual workspace illustration.
- workspace-network-mobile.svg/png: compact mobile composition.
- manifest.json: machine-readable glyph names and geometry values.

Build from the repository root:
  python design/build_interface.py
  node design/render_interface.cjs
The renderer uses sharp. No rendering library is needed by the website.

The GitHub mark shown on the site identifies GitHub; it is not part of this set.
