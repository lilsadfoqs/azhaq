AZHAQ / CONTOUR IDENTITY

Concept
The lowercase a is a boundary around a mapped interior. Chamfered curves and
the lower-right diagonal opening are shared with the custom wordmark. The
contour relief is built from the same SVG path, repeated in depth.

Masters
- mark.svg: main one-colour mark, viewBox 0 0 64 64.
- mark-micro.svg: separate pixel-grid master, viewBox 0 0 16 16.
- wordmark.svg: custom outlined lowercase azhaq. No font dependency.
- lockup.svg: fixed symbol + wordmark relationship.
- *-light.svg: pale fill, for dark backgrounds.
- *-dark.svg: dark fill, for light backgrounds.
- favicon.svg: micro mark with native colour-scheme support.
- favicon-32.png: fixed light tile for legacy favicon support.
- avatar.png / avatar.svg: 512 px square profile image.
- mark-{light,dark}-{16,24,32,64,128,256}.png: transparent PNG sizes.

Use
Use the micro master at 16–23 px and the main mark from 24 px upward.
Give the mark clear space of at least 25% of its width.
Do not stretch, rotate or add outlines to the primary logo.
Minimum lockup width: 140 px.
Keep the primary logo in one flat colour. Shading belongs only to illustrations.

Colours
Ink #111614
Paper #ECF0ED
Sage #B9CEC1

Illustrations
contour-relief.svg and survey-sheet.svg are conceptual brand illustrations.
They do not represent an actual software UI or scan result.

Development
The source repository includes design/geometry.py and design/build_identity.py.
All logo glyphs are explicit vector paths; no icon library or logo font is used.
The identity sheet documents the selected direction and optical sizes.
