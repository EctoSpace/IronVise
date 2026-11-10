# deepmerge security patch

Upstream: https://github.com/TehShrike/deepmerge, npm 4.3.1 (MIT license included).
GHSA-gcqx-w48m-w2h4: https://github.com/TehShrike/deepmerge/issues/273
Registry latest checked 5 November 2026: 4.3.1, no supported patched release.
Local patch rejects __proto__, constructor and prototype from BOTH the target
clone and source merge, including null-prototype inputs and custom merge hooks.
Patched index.js and both distributed entrypoints. No advisory suppression.
Version suffix identifies a local patch, not an upstream security release.
Remove override after upstream publishes a compatible fix; run regression tests.
