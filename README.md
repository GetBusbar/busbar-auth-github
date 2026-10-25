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

**GitHub-OAuth login for busbar** — a login-capable auth plugin (auth ABI v2, 1.5.2
token-exchange). A user signs in with GitHub; busbar establishes their identity as
`github:<login>` with `github:org/<org>` group memberships, then resolves those groups to policy
through the operator's `auth.role_bindings.github:` bindings.

It is a **separate plugin from `busbar-auth-oidc`**, and independent of the busbar core release.

### Why GitHub is its own plugin (not an OIDC config)

GitHub OAuth issues an **opaque** access token and **no `id_token` JWT**, so the OIDC/JWKS
verify path does not apply — there is nothing to verify offline. Identity instead comes from
GitHub's REST API (`/user`, `/user/orgs`). On busbar 1.6 the plugin runs those hops itself over its
one outbound `http` need, and holds its own confidential-client **secret** (the kernel resolves
`browser_login.client_secret` into `OpenIn.secrets`). (The statically linked 1.5.x `GithubModule`
shape instead *describes* each hop as a multi-hop `Exchange` and the core executes it, injecting
the secret into the token-exchange hop.)

### The login flow (hop sequence)

| step | `complete_login` input | plugin returns |
|------|------------------------|----------------|
| begin | `begin_login` (core-minted `state`, PKCE `code_challenge`) | `Authorize(<github authorize URL>)` |
| 1 | `code` + `redirect_uri` + `code_verifier`, no token response | `Exchange`: `POST .../login/oauth/access_token` (`secret_form_field = client_secret`) |
| 2 | token response fed back | `Exchange`: `GET .../user` |
| 3 | `/user` JSON fed back | `Exchange`: `GET .../user/orgs` (or `Identify` now if `fetch_orgs = false`) |
| 4 | `/user/orgs` JSON fed back | `Identify(github:<login>` + `github:org/<org>` groups) |

Fail-closed (`Reject`) on any non-2xx, missing `access_token`, missing `login`, or malformed JSON.
GitHub answers its token endpoint with **HTTP 200 even on a bad code** (an `{"error":...}` body with
no `access_token`) — that is treated as a rejection, never a success with an empty token.

## Config

Only `client_id` is required to parse, but **write `token_base`, `api_base` and `authorize_base`
out in the settings even for github.com**: the hop allowlist is built only from the URL strings
written in the settings (1.5.5 parity), so a base left at its default is not allowlisted and every
hop to it is refused. The defaults below apply to the parsed config only. The `client_secret` is
**never** in this config — it is `browser_login.client_secret`, which the kernel delivers to the
plugin.

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
| `api_base` | `https://api.github.com` | GHES: `https://<host>/api/v3` |
| `authorize_base` | `https://github.com` | GHES: `https://<host>` |
| `token_base` | `https://github.com` | GHES: `https://<host>` |
| `fetch_orgs` | `true` | `false` = login-only, no org groups, one fewer hop |
| `ca_cert_pem` | *(none)* | GHES internal-CA trust (see ABI note below) |

The config is `deny_unknown_fields` (a typo fails loudly at boot) and every non-required field is
additive-friendly (`serde(default)`).

### GitHub Enterprise Server (GHES)

Point the three base URLs at your instance — authorize/token live at `https://<host>/login/oauth/...`
and the REST API at `https://<host>/api/v3`:

```json
{
  "client_id": "...",
  "api_base": "https://ghe.corp.example/api/v3",
  "authorize_base": "https://ghe.corp.example",
  "token_base": "https://ghe.corp.example",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n..."
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

The `busbar-auth-github` crate is the reusable logic (statically linkable); `busbar-auth-github-plugin`
is the thin `cdylib` that exports the auth C ABI via `busbar_contract::export_door!` (exporting
`busbar_auth_github::door::door`).

### ABI notes / caveats

- **PKCE.** GitHub supports S256 PKCE on the web authorization-code flow (2024+). The core-minted
  `code_challenge` is always sent; a GitHub OAuth App that has not opted into PKCE simply ignores it,
  and the paired `code_verifier` rides the token exchange harmlessly.
- **Request headers on GET hops.** GitHub REST calls **require** an `Authorization: Bearer <token>`
  and a `User-Agent` header. Auth ABI v2's `LoginHop` / `HttpRequest` carries a `headers:
  Vec<(String,String)>` field for exactly this; `busbar_auth_github::userinfo_headers()` computes the
  headers, and `build_userinfo_get`/`build_orgs_get` attach them directly to the `/user` and
  `/user/orgs` hops. Headers are sanitized (CR/LF/NUL and hop-control headers rejected) and a hop
  only goes to a host on the allowlist built from the settings' URLs.
- **`ca_cert_pem` delivery.** The plugin's one outbound `http` need carries no CA, so this GHES CA
  value still has no delivery channel. It is accepted here for forward-compatibility and to capture
  operator intent.
- **Multi-hop flow state.** The access token is seen once (the token response) but is needed to
  authenticate both GETs, and the `/user` identity is needed at the `/user/orgs` step. On 1.6
  each flow (`LoginFlow`) owns this state, so concurrent logins never share a slot. (The legacy
  static-link `GithubModule` keyed it by the core-held PKCE `code_verifier`, falling back to `code`, and rejected a
  feedback call carrying neither.)

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
