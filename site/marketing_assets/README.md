# Website demo media

The videos and screenshots show the current IronVise 0.8 interface using the
fixed demonstration fixtures in `gui/tests/visual/tauri-mock.ts` and the
certificate export fixtures in `gui/scripts/record-site-media.spec.ts`. They are
interface walkthroughs; the displayed sessions, hashes and verification results
are example data, not evidence from a live security evaluation. Each recording
and screenshot carries a visible demonstration-data label.

Regenerate locally with Node dependencies and Playwright Chromium installed:

```sh
./scripts/update-site-media.sh
```

This records the current UI, exports browser-compatible H.264 MP4s and animated
GIFs with FFmpeg, and refreshes the nine website screenshots. It does not run
GitHub Actions or publish the website. Review the videos and screenshots before
committing them.
