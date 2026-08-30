# Suite-host assets

Served by `conformance::http` on `conformance.pqcrypta.com`, which is its own
origin under a `default-src 'self'` CSP — so every stylesheet, script and image
the page references has to come from a route on this host. They are embedded with
`include_str!`/`include_bytes!` so the binary is self-contained and the page can
never reference an asset that is not being served.

`bg.*` and `cursor.*` are the same background animation and pointer as the
documentation page at `pqcrypta.com/conformance/`, which lives in the site repo
at `public/conformance/`. This crate is a **separate git repository**, so it
cannot include from there and keeps its own copy. Change one, change both — the
two pages are meant to look like one thing.

## The site navigation

`menu.html` is the rendered output of `public/fun/menu.php`, captured once and
embedded, with `menu.css`, `menu.js`, `error-menu.js`, `mini-countdown.js` and
`quantum-countdown.css` served alongside it at the same paths the markup
references. The menu's own links are already absolute, so it works across the
hostname boundary unchanged — one exception, `/why/index.php#call-to-action`,
was made absolute by hand.

Two deliberate differences from the site copy:

- the **live news widget is removed**. It streams from `api.pqcrypta.com` and
  proxies images through a relative PHP endpoint, neither of which exists on
  this host, so it would sit on "Loading news..." forever. The link to the news
  page stays.
- the menu asks `api.pqcrypta.com/auth` whether the visitor is signed in. That
  origin is not in the API's CORS allowlist, so the call fails and the menu
  shows the signed-out state. It is wrapped in a `catch`, so nothing breaks.

Re-capture this file whenever the site menu changes: it is a snapshot, and
nothing detects drift automatically.
