<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-github

The GitHub-OAuth login module as a droppable busbar plugin: a cdylib exporting the auth C ABI (login-capable). Drop it in the plugins folder and add github to auth.chain with a browser_login block (the core injects client_secret).

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `github` | `busbar-auth-github-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-github/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-github/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

<!-- SPDX-License-Identifier: Apache-2.0 -->

<a href="https://codecov.io/gh/GetBusbar/busbar-auth-github"><img src="https://codecov.io/gh/GetBusbar/busbar-auth-github/branch/dev/graph/badge.svg" alt="Coverage"></a>

**GitHub-OAuth login for busbar** — a login-capable auth plugin (the auth kind's door, auth ABI
v3). A user signs in with GitHub; busbar establishes their identity as
`github:<login>` with `github:org/<org>` group memberships, then resolves those groups to policy
through the operator's `auth.role_bindings.github:` bindings.

It is a **separate plugin from `busbar-auth-oidc`**, and independent of the busbar core release.

### Why GitHub is its own plugin (not an OIDC config)

GitHub OAuth issues an **opaque** access token and **no `id_token` JWT**, so the OIDC/JWKS
verify path does not apply — there is nothing to verify offline. Identity instead comes from
GitHub's REST API (`/user`, `/user/orgs`). On busbar 1.6 the plugin runs those hops itself over its
one outbound `http` need, and holds its own confidential-client **secret** (the kernel resolves
`browser_login.client_secret` into `OpenIn.secrets`).

### The login flow (hop sequence)

| step | input | the plugin |
|------|-------|------------|
| begin | `begin_login` (kernel-minted `state`, PKCE `code_challenge`) | answers the GitHub authorize URL |
| 1 | `complete_login`: `code` + `redirect_uri` + `code_verifier` | `POST .../login/oauth/access_token` with its own `client_secret` |
| 2 | the token response | `GET .../user` (bearer) |
| 3 | the `/user` JSON | `GET .../user/orgs` (or identifies now if `fetch_orgs = false`) |
| 4 | the `/user/orgs` JSON | identifies `github:<login>` + `github:id/<id>` + `github:org/<org>` groups |

Declined (a bad credential, 401) on any other non-2xx, a missing `access_token`, a missing `login`,
or malformed JSON. An outage (503, retryable) when GitHub answers `5xx` or `429`, when a hop cannot
be made (refused, connect, TLS, timeout), or when its reply passes 256 KiB. An `id_token` on a hop
answer (never from github.com) must carry the nonce minted at begin, else the sign-in fails its
security check (400).
GitHub answers its token endpoint with **HTTP 200 even on a bad code** (an `{"error":...}` body with
no `access_token`) — that is treated as a rejection, never a success with an empty token.

## Config

`client_id`, `token_base` and `api_base` are required, **even for github.com**: the hop allowlist
is built only from the URL strings written in the settings (1.5.5 parity), so `validate`/`open`
refuse settings that leave either at its default (`settings.token_base: must be written out: the
hop allowlist is built only from URLs in the settings`). `authorize_base` is a browser redirect, not
a hop, and may stay at its default. An empty `client_id`, or a base that is not an http(s) URL with
a host, is refused too. The `client_secret` is **never** in this config — it is
`browser_login.client_secret`, which the kernel delivers to the plugin.

```json
{
  "client_id": "Iv1.abc123",
  "scopes": ["read:org", "read:user"],
  "api_base": "https://api.github.com",
  "authorize_base": "https://github.com",
  "token_base": "https://github.com",
  "fetch_orgs": true
}
```

| field | default | notes |
|-------|---------|-------|
| `client_id` | *(required)* | GitHub OAuth App / GitHub App client id |
| `scopes` | `["read:org","read:user"]` | `read:org` powers the org→group hop |
| `api_base` | *(required)* | `https://api.github.com`; GHES: `https://<host>/api/v3` |
| `authorize_base` | `https://github.com` | GHES: `https://<host>` |
| `token_base` | *(required)* | `https://github.com`; GHES: `https://<host>` |
| `fetch_orgs` | `true` | `false` = login-only, no org groups, one fewer hop |
| `ca_cert_pem` | *(none)* | An extra trusted root (PEM) for a GHES behind an internal CA (see below) |

The config is `deny_unknown_fields` (a typo fails loudly at boot). Every refusal is the contract's
instance-relative line, `settings.<path>: <reason>` (`settings: <reason>` for the document), and
never quotes a value: a mistyped value is written `***` (`settings.client_id: invalid type: integer
\`***\`, expected a string`). A client secret that is not UTF-8 answers
`secrets: \`client_secret\` is not UTF-8`.

### GitHub Enterprise Server (GHES)

Point the three base URLs at your instance — authorize/token live at `https://<host>/login/oauth/...`
and the REST API at `https://<host>/api/v3`:

```json
{
  "client_id": "...",
  "api_base": "https://ghe.corp.example/api/v3",
  "authorize_base": "https://ghe.corp.example",
  "token_base": "https://ghe.corp.example"
}
```

### Groups

Each org the user belongs to becomes a group string `github:org/<org-login>`, mapped to policy by the
operator's `auth.role_bindings.github:`. (Team-level groups `github:team/<org>/<team-slug>` are a
straightforward extension via a `/user/teams` hop; not enabled by default.)

## Build

```
cargo build --release        # produces the cdylib plugin (libbusbar_auth_github_plugin.{so,dylib,dll})
cargo clippy --all-targets -- -D warnings
cargo test
```

The `busbar-auth-github` crate (`auth-github/`) is the reusable logic (statically linkable);
`busbar-auth-github-plugin` (`auth-github-plugin/`) is the thin `cdylib` that exports the auth C ABI via `busbar_contract::export_door!` (exporting
`busbar_auth_github::door::door`).

### ABI notes / caveats

- **PKCE.** GitHub supports S256 PKCE on the web authorization-code flow (2024+). The core-minted
  `code_challenge` is always sent; a GitHub OAuth App that has not opted into PKCE simply ignores it,
  and the paired `code_verifier` rides the token exchange harmlessly.
- **Request headers on GET hops.** GitHub REST calls **require** an `Authorization: Bearer <token>`
  and a `User-Agent` header. `busbar_auth_github::userinfo_headers()` gives the public ones
  (`User-Agent`, `Accept`), and `build_userinfo_get`/`build_orgs_get` attach them to the `/user`
  and `/user/orgs` hops. Headers are sanitized (CR/LF/NUL and hop-control headers rejected) and a
  hop only goes to a host on the allowlist built from the settings' URLs.
- **Credentials are the SDK chip's.** The client secret and the access token are
  `abi::sdk::cred::Cred`s: the secret goes out only as a sealed `FormBody` value, the token only as
  the sealed `authorization: Bearer` field, both written by the SDK at the wire and required to go
  out on a secured connection when their base is `https`. The plugin holds neither as text; the
  code, the verifier and every hop answer are wiped when they go, and nothing formats them.
- **`ca_cert_pem`.** The Statement declares two outbound `http` needs: one trusting
  `settings.ca_cert_pem` beside the public roots, one the public roots only. A config that names a
  `ca_cert_pem` goes out on the first, any other on the second; the host's connector does the TLS,
  and certificate validation is only widened, never disabled. A value with no PEM certificate in it
  is refused (`settings.ca_cert_pem: not a PEM certificate (no -----BEGIN CERTIFICATE----- line)`).
- **Multi-hop flow state.** The access token is seen once (the token response) but is needed to
  authenticate both GETs, and the `/user` identity is needed at the `/user/orgs` step. Each flow
  (`LoginFlow`) owns this state, so concurrent logins never share a slot; a finished flow holds
  neither.
- **Reply cap.** Every hop's reply is capped at 256 KiB (`MAX_HOP_REPLY_BYTES`, the exchange's
  `reply_limit`); a reply past it ends the login as an outage.

## Tests

```bash
cargo test --workspace --locked
```

`auth-github-plugin/tests/conformance.rs` runs busbar's published conformance suite (both doors,
the far ends in `conformance.json`) and mounts the test kit's host
(`tests/support/conformance_host.rs`). `tests/e2e.rs` is the live end-to-end against a real busbar
and a wiremock GitHub (CI's `wiremock` service).

## License

Apache-2.0. See [LICENSE](LICENSE).
