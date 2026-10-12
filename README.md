# openconnect-saml

Connect to a Cisco AnyConnect gateway that authenticates with SAML/SSO, using
your ordinary desktop browser and plain `openconnect`. Written in
[Jennifer](https://github.com/jennifer-language/jennifer).

No embedded webview, no Playwright: your real browser does the login, so Duo
push, hardware keys and saved passwords work as they always do. With a
Chromium-based browser the resulting cookie is collected for you.

```sh
openconnect-saml probe        # what does my gateway want?
openconnect-saml connect      # log in and bring the tunnel up
openconnect-saml status
openconnect-saml disconnect
```

## Requirements

- `openconnect`
- `jennifer` **>=0.25.0**;
  the program declares `pragma-jennifer-version: >=0.25.0`
- a browser; Chromium-based (chromium, chrome, brave, vivaldi, edge) also gets
  automatic cookie capture

## Install

With [jvc](https://jvc.jennifer-lang.dev/), from the `deck.toml` in this
repository:

```sh
jvc app install https://github.com/mplx/openconnect-saml
```

Installs the newest release tag into `~/.local/share/jvc/apps/` and links
`~/.local/bin/openconnect-saml` at it. The tree is unpacked whole, so `bin/`
still finds `../src/saml.j`. `--version "^0.3"` pins a range;
`jvc app update` / `jvc app uninstall` take it from there. Nothing is vendored:
every import is a bundled stdlib module.

Not `--scope system` - this runs as your desktop user and escalates for the
tunnel itself. See [Notes](#notes).

An app install writes no configuration. Copy the template out once:

```sh
install -Dm600 ~/.local/share/jvc/apps/openconnect-saml/config.example.toml \
               ~/.config/openconnect-saml/config.toml
```

As an OS package instead:

```sh
cd packaging/arch && makepkg -si       # runs the test suite first
```

By hand, keeping the two files' relative layout (`bin/` imports `../src/saml.j`;
a symlink is fine, Jennifer resolves imports against the real path):

```sh
install -Dm755 bin/openconnect-saml ~/.local/lib/openconnect-saml/bin/openconnect-saml
install -Dm644 src/saml.j           ~/.local/lib/openconnect-saml/src/saml.j
ln -sf ../lib/openconnect-saml/bin/openconnect-saml ~/.local/bin/openconnect-saml
install -Dm600 config.example.toml  ~/.config/openconnect-saml/config.toml
```

## Configuration

`~/.config/openconnect-saml/config.toml`, or `--server` on the command line.
Every top-level table is a profile; a `default` key picks one.

```toml
default = "work"

[work]
server  = "https://vpn.example.com/saml"   # group URL, path and all
browser = "chromium"
```

**Put the whole group URL in `server`.** On a Cisco gateway the URL path selects
the tunnel group (it becomes `<group-access>`); `--group` (`<group-select>`) is
widely ignored. `probe` prints the group the gateway resolved to, so a wrong
path is visible at a glance.

| key | |
|---|---|
| `server` | gateway URL including the group path |
| `browser` | command that opens a URL; Chromium-based enables capture. `-` to print only |
| `sudo` | privilege helper for the tunnel (`""` if already root) |
| `capture` | `auto` (default) / `cdp` / `paste` |
| `cdpPort`, `browserProfile`, `captureTimeout` | capture browser knobs |
| `user`, `passwordCommand`, `factor` | browserless mode |
| `servercert` | pin the certificate yourself instead of using the gateway's |
| `insecure`, `version`, `extra`, `group` | TLS opt-out, claimed client version, extra openconnect flags, `<group-select>` |

## Commands

| | |
|---|---|
| `connect [profile]` | authenticate, then start the tunnel in the background |
| `cookie [profile]` | authenticate and print `COOKIE` / `CONNECT_URL` / `FINGERPRINT` |
| `probe [profile]` | report how the gateway authenticates |
| `status [profile]` | is the tunnel up? (exit 0/1) |
| `disconnect [profile]` | stop a tunnel started by `connect` |

Flags: `--server`, `--group`, `--browser`, `--sudo`, `--mode`, `--capture`,
`--user`, `--password-command`, `--factor`, `--debug-dir`, `--print`, `-v`,
`-k`. A usage mistake exits 2; `--help` works per subcommand.

## How it works

`connect` asks the gateway which shape of SAML it speaks.

**external** - the gateway is configured with `saml external-browser`, which
openconnect implements natively. All this adds is running
`openconnect --authenticate` as you, so the browser opens in your session, then
starting only the tunnel under `sudo` with the cookie on stdin.

**token** - the classic flow, where the token arrives as a cookie on the
gateway's domain. This speaks the `<config-auth>` XML itself: POST `init`, read
back the login URL and the gateway's `<opaque>` blob, collect the cookie, POST
`auth-reply` with the blob echoed verbatim, then hand `openconnect` the
`<session-token>` and the certificate hash the gateway reported.

## Collecting the cookie

Set a Chromium-based `browser` and there is nothing to paste: it is launched
with `--remote-debugging-port`, you log in normally, and the token is read out
over the DevTools protocol as soon as the gateway sets it. This is the only way
to get it automatically - the cookie is **`HttpOnly`**, so no page script or
bookmarklet can see it.

The capture browser uses its own persistent profile
(`~/.cache/openconnect-saml/browser`): separate so it never collides with a
browser you have open, persistent so the IdP session and any "remember this
device" survive to the next connect.

Otherwise (Firefox, or `capture = "paste"`) you are given the login URL and
asked for the cookie - **F12 -> Application/Storage -> Cookies**. The prompt
takes the bare value, a `name=value` pair, a whole `Cookie:` header, or the
final URL.

## Browserless mode

```sh
openconnect-saml connect --mode browserless --user jdoe
```

Opt-in, no browser: the IdP's HTML forms are walked directly until the gateway
sets its cookie. Only works where the login is plain forms - **a second factor
or a JavaScript page ends it**, naming what it hit. Duo is recognised by name.

The password comes from `passwordCommand` (e.g. `pass show vpn/work`), else
`$OPENCONNECT_SAML_PASSWORD`, else a hidden prompt. It is never read from the
config file.

Two deliberate refusals: it **never resubmits credentials** (a second credential
form means the first was rejected - retrying is how accounts get locked), and it
**never guesses at a form it does not understand**.

Where the IdP offers factors as a form, `--factor passcode` picks one; the name
is matched case-insensitively as a substring of each control's `name`, `value`
and `id`. Without it the first control is taken. A real choice with no match is
an error listing the options, not a guess.

Failures name the page, the fields found and the trail of URLs walked. `-v`
shows each step; `--debug-dir DIR` saves every page (they contain CSRF tokens
and SAML assertions, so the directory is created `0700` and the files `0600`).

## Notes

- **sudo.** `connect` uses `sudo -n`, because the child has no terminal to
  prompt on. Run `sudo -v` first, or `--print` to get the command and run it
  yourself.
- **Backgrounding.** openconnect daemonises only once the tunnel is up, so a
  successful `connect` means connected. Pid in
  `/run/openconnect-saml-<profile>.pid`, output in `...log` - read that first
  when a tunnel drops. The redirect is load-bearing: a daemon holding the
  inherited pipes would never let the launching call return.
- **The cookie never reaches the process list** - it goes over stdin.
- **Certificate pinning is automatic**: the gateway reports its own hash at the
  end of the login, and that becomes `--servercert`.
- **TLS is not optional.** A plain `http://` gateway is refused unless the host
  is loopback or `--insecure` is given. Browserless mode refuses `--insecure`
  outright and refuses any non-`https` hop: the form's `action` decides where the
  password goes. It prints the host that receives it.
- **`disconnect` confirms the pid is still openconnect** (`/proc/<pid>/cmdline`)
  before signalling it as root. Pid files outlive tunnels; Linux reuses pids.
- **The capture browser is cleaned up on every exit path**, timeout included, so
  no live SSO session is left behind an open debug port. That port carries no
  `--remote-allow-origins`: `*` would let any page in any local browser drive it
  and read the `HttpOnly` cookie.
- Some gateways answer `<error id="96">VPN Server internal error.</error>` to a
  client that merely advertises external-browser support. That is treated as a
  no, and `probe` reports it.

## Layout and tests

| | |
|---|---|
| `bin/openconnect-saml` | executable; imports the module, exits with its status |
| `src/saml.j` | the program, as a module |
| `src/saml_test.j` | unit tests - a white-box overlay spliced onto `saml.j` |
| `tests/run.sh` | the whole suite; what CI and `makepkg` run |
| `tests/integration.sh` | end-to-end tests against `tests/mock-gateway.j` |
| `tests/check-versions.sh`, `tests/check-docs.j` | version and doc-comment gates |
| `deck.toml` | the app manifest `jvc app install` reads |
| `packaging/arch/PKGBUILD` | the Arch package |

```sh
tests/run.sh              # parse, format, lint, docs, versions, unit, integration
tests/run.sh 0.3.0        # ... and require that version, as a tag build does
```

The logic sits in `src/saml.j` rather than the executable so `saml_test.j` can
splice it and reach the private surface. The PKGBUILD sits in `packaging/arch/`
because makepkg builds in `$startdir/src` and `makepkg -C` empties it - at the
root that would be this project's own `src/`. The mock gateway is Jennifer, and
the integration tests stub `openconnect`, so the suite needs no VPN, browser or
root.

## Troubleshooting

Start with `openconnect-saml probe -v`.

| | |
|---|---|
| `VPN Server internal error.` | wrong URL path, so wrong tunnel group - check `probe`'s `tunnel group` line |
| `offered no <sso-v2-login> URL` | that group is not using SAML |
| `expected an auth-request ...` | wrong URL, or a portal in front of the gateway |
| `did not complete the login` | token rejected; it expires quickly, so retry promptly |
| `browser never opened its debug port` | another browser holds that profile or port - change `cdpPort` |
| `browser exited without opening its debug port` | the browser's own stderr is quoted underneath; that line is the reason |
| certificate complaints from openconnect | copy the `pin-sha256:` value it prints into `servercert` |
