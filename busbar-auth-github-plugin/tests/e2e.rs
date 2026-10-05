// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin-SIDE live end-to-end for the GitHub login plugin — the mirror of `auth-oidc-plugin`'s
//! `tests/e2e.rs`, testing THIS plugin's OWN token-exchange direction (the GET browser-redirect flow
//! where the CORE executes the module-described token → `/user` → `/user/orgs` hops).
//!
//! GitHub issues an OPAQUE access token (no id_token/JWKS to verify offline), so — unlike OIDC — there
//! is no held-token `POST /auth/token` path to exercise, and the hops are executed by the CORE, not by
//! a direct plugin-ABI call. The only faithful test is therefore a REAL busbar boot driving the real
//! GET flow. The GitHub REST endpoints are stubbed by a READY-MADE WireMock container (never a
//! hand-rolled server), provided by CI as a service container and addressed via
//! `BUSBAR_TEST_WIREMOCK_URL` (mirrors how the store plugins read `BUSBAR_TEST_POSTGRES_URL`). This
//! test registers its stub mappings over WireMock's own `/__admin` API, packs the real plugin cdylib
//! with the real `busbar-plugin-pack`, boots the real `busbar` binary with an `identity-providers.github`
//! pointed at WireMock, and drives GET begin → callback so the CORE really runs the hops.
//!
//! GATING: when `BUSBAR_TEST_WIREMOCK_URL` is unset (a local run without the container) the test
//! SKIPS loudly — never a silent-vacuous pass — exactly like the store plugins' service-gated tests.
//! Under CI, the plugin-ci `service: wiremock` arm sets the env var and the test RUNS.

use std::io::Write as _;

/// The WireMock base URL a CI service container exposes (e.g. `http://127.0.0.1:8080`). Absent ⇒ skip.
fn wiremock_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_WIREMOCK_URL") {
        Ok(u) if !u.trim().is_empty() => Some(u.trim().trim_end_matches('/').to_string()),
        _ => None,
    }
}

/// The busbar checkout the live e2e builds the REAL `busbar` and `busbar-plugin-pack` binaries from:
/// `BUSBAR_CHECKOUT`, a checkout of GetBusbar/busbar at `.busbar-ref` field 1 (this repo's CI `e2e` job
/// checks it out and sets the variable). This repo builds against busbar by git rev, not a sibling
/// path, so the binaries' source is named explicitly. Unset ⇒ the live leg cannot run, and says so.
fn busbar_root() -> std::path::PathBuf {
    let dir = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the live e2e builds the real busbar binaries from a checkout of \
         GetBusbar/busbar at .busbar-ref (ci.yml `e2e` sets it)",
    );
    std::path::PathBuf::from(dir)
        .canonicalize()
        .expect("BUSBAR_CHECKOUT names an existing busbar checkout")
}

/// Build (cargo-cached) and return the real `busbar` + `busbar-plugin-pack` binaries from the sibling.
fn build_real_binaries() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = busbar_root();
    // Two invocations: in busbar 1.6.0 `busbar-plugin-pack` is a feature-gated bin of the
    // `busbar-plugin-loader` package (`--features pack`), not a package of its own, and building it
    // separately keeps the `pack` feature out of the `busbar` build.
    for args in [
        &["build", "--release", "-p", "busbar", "--bin", "busbar"][..],
        &[
            "build",
            "--release",
            "-p",
            "busbar-plugin-loader",
            "--features",
            "pack",
            "--bin",
            "busbar-plugin-pack",
        ][..],
    ] {
        let status = std::process::Command::new("cargo")
            .args(args)
            .current_dir(&root)
            // The binaries are read back from `<sibling>/target/release` below, so the build must
            // land there: an inherited CARGO_TARGET_DIR (set for the outer `cargo test`) would
            // redirect it into the plugin's own target dir.
            .env_remove("CARGO_TARGET_DIR")
            .status()
            .expect("run cargo build for busbar / busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    (
        root.join("target/release/busbar"),
        root.join("target/release/busbar-plugin-pack"),
    )
}

/// Locate the built `busbar_auth_github_plugin` cdylib (checks the uplifted profile dir and target/deps,
/// newest wins — same helper shape as auth-oidc's `plugin_path`). Under CI a missing cdylib is fatal.
fn plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_auth_github_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "busbar_auth_github_plugin cdylib not built under CI (run `cargo test --workspace`)"
        );
    }
    candidate
}

/// Pack the plugin cdylib into a real tarball via the real `busbar-plugin-pack` (alias `github`).
fn pack_github(pack_bin: &std::path::Path, so: &std::path::Path, out: &std::path::Path) {
    let status = std::process::Command::new(pack_bin)
        .args([
            "pack",
            "--lib",
            so.to_str().unwrap(),
            "--name",
            "busbar-auth-github",
            "--alias",
            "github",
            "--kind",
            "auth",
            "--version",
            "0.0.0-e2e",
            "--publisher",
            "busbar",
            "--description",
            "github plugin-side e2e",
            "--license",
            "Apache-2.0",
            "--out",
            out.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the github plugin must succeed");
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Register the GitHub stub mappings on WireMock over its admin API (equivalent to the JSON files under
/// busbar/scripts/fixtures/auth-github-wiremock, kept here so the plugin's own CI is self-contained).
fn register_wiremock_stubs(client: &reqwest::blocking::Client, base: &str) {
    // Poll WireMock's admin API until it answers (the service container may still be starting).
    let mut ready = false;
    for _ in 0..60 {
        if client
            .get(format!("{base}/__admin/mappings"))
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(ready, "WireMock admin API never became ready at {base}");
    // Fresh slate so a rerun does not stack duplicate stubs.
    let _ = client.post(format!("{base}/__admin/mappings/reset")).send();
    let mappings = [
        serde_json::json!({
            "request": { "method": "POST", "urlPath": "/login/oauth/access_token" },
            "response": { "status": 200, "headers": { "Content-Type": "application/json" },
                "jsonBody": { "access_token": "gho_test", "token_type": "bearer", "scope": "" } }
        }),
        serde_json::json!({
            "request": { "method": "GET", "urlPath": "/user" },
            "response": { "status": 200, "headers": { "Content-Type": "application/json" },
                "jsonBody": { "login": "octotest", "id": 12345, "name": "Octo Test" } }
        }),
        serde_json::json!({
            "request": { "method": "GET", "urlPath": "/user/orgs" },
            "response": { "status": 200, "headers": { "Content-Type": "application/json" },
                "jsonBody": [ { "login": "testorg" } ] }
        }),
    ];
    for m in mappings {
        let r = client
            .post(format!("{base}/__admin/mappings"))
            .json(&m)
            .send()
            .expect("register a WireMock stub");
        assert!(
            r.status().is_success(),
            "WireMock rejected a stub mapping: {}",
            r.status()
        );
    }
}

/// Decode the busbar login cookie (base64url(JSON)) and read its `state` (the CSRF value the callback
/// must echo — a real browser round-trips the HttpOnly cookie; the test reads it out of the cookie).
fn cookie_state(cookie_value: &str) -> String {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cookie_value)
        .expect("cookie is base64url");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("cookie is JSON");
    v["state"]
        .as_str()
        .expect("cookie carries state")
        .to_string()
}

/// Pull the issued api_key out of the key-issued HTML (`... id="key">KEY<`).
fn issued_key_from_html(html: &str) -> Option<String> {
    let marker = "id=\"key\">";
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest.find('<')?;
    Some(rest[..end].to_string())
}

fn wait_for_health(client: &reqwest::blocking::Client, url: &str, child: &mut std::process::Child) {
    for _ in 0..150 {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("busbar exited early during health poll: {status}");
        }
        if client
            .get(url)
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("busbar did not become healthy at {url}");
}

/// THE plugin-side proof: a REAL busbar boot drives the github GET flow; the CORE executes the real
/// token/user/orgs hops against WireMock; a self-scoped key is minted for `github:octotest` bound
/// through role `github:org/testorg`, and that key is accepted on the data plane (not 401).
#[test]
fn github_get_flow_mints_key_via_core_executed_hops() {
    let Some(wm) = wiremock_url() else {
        eprintln!(
            "skip: BUSBAR_TEST_WIREMOCK_URL unset — github live e2e needs the WireMock service \
             container (set by the plugin-ci `service: wiremock` arm). Skipping (local, no docker)."
        );
        return;
    };
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: busbar_auth_github_plugin cdylib not built");
        return;
    };
    let (busbar_bin, pack_bin) = build_real_binaries();

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none()) // capture the 302 + Set-Cookie ourselves
        .build()
        .unwrap();
    register_wiremock_stubs(&client, &wm);

    let work = std::env::temp_dir().join(format!(
        "busbar-github-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    pack_github(
        &pack_bin,
        &so_path,
        &plugins_dir.join("busbar-auth-github.tar.gz"),
    );

    let data_port = free_port();
    let signing_key = work.join("signing.key");
    {
        let out = std::process::Command::new(&busbar_bin)
            .arg("--generate-signing-key")
            .output()
            .expect("generate signing key");
        assert!(out.status.success());
        let mut f = std::fs::File::create(&signing_key).unwrap();
        f.write_all(&out.stdout).unwrap();
    }

    let providers = work.join("providers.yaml");
    // Unreachable upstream (127.0.0.1:9): the data-plane assertion is "the issued key AUTHENTICATES"
    // (not 401), not "the mock chat returns 200" — mirrors auth-oidc's live e2e.
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();

    let config = work.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:{data_port}\"\n\
             public_url: \"https://gate.busbar.e2e\"\n\
             store: {{ module: memory }}\n\
             advanced:\n  allow_destinations: [\"127.0.0.1\", \"localhost\"]\n\
             identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
             \x20 github:\n    module: github\n    browser_login:\n      client_id: \"Iv1.e2eclient\"\n\
             \x20     client_secret: {{ env: BUSBAR_GH_CLIENT_SECRET }}\n\
             \x20   settings:\n      token_base: \"{wm}\"\n      api_base: \"{wm}\"\n      authorize_base: \"{wm}\"\n\
             auth:\n  key_ttl: \"7d\"\n  signing_key: {{ file: \"{signing}\" }}\n  chain:\n    - keys\n\
             \x20 admin_auth: [admin-tokens]\n\
             \x20 role_bindings:\n    github:\n      \"github:org/testorg\":\n        group: eng-team\n\
             plugins:\n  enabled: true\n  dir: {plugins}\n  trust:\n    allow_unsigned: true\n\
             groups:\n  eng-team:\n    limits:\n      - {{ requests: 1000000, per: day }}\n\
             \x20   child_default:\n      limits:\n        - {{ budget: 5000, per: month }}\n        - {{ requests: 1000, per: day }}\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            signing = signing_key.display(),
            plugins = plugins_dir.display(),
        ),
    )
    .unwrap();

    let mut child = std::process::Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("MOCK_KEY", "unused")
        .env("BUSBAR_GH_CLIENT_SECRET", "e2e-secret")
        .env("BUSBAR_ADMIN_TOKEN", "e2e-admin-token")
        .env("BUSBAR_STATE_FILE", "")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn busbar with identity-providers.github");
    let base = format!("http://127.0.0.1:{data_port}");
    wait_for_health(&client, &format!("{base}/healthz"), &mut child);

    // begin: GET ?method=github → 302 + login cookie carrying state.
    let begin = client
        .get(format!("{base}/auth/token?method=github"))
        .send()
        .expect("GET begin");
    let cookie_value = begin
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|c| {
            c.strip_prefix("busbar_login=")
                .map(|r| r.split(';').next().unwrap_or("").to_string())
        })
        .expect("begin sets the busbar_login cookie");
    let state = cookie_state(&cookie_value);

    // callback: GET ?code=…&state=… WITH the cookie → the CORE executes the token/user/orgs hops.
    let cb = client
        .get(format!("{base}/auth/token?code=e2e-code&state={state}"))
        .header(
            reqwest::header::COOKIE,
            format!("busbar_login={cookie_value}"),
        )
        .send()
        .expect("GET callback");
    assert!(
        cb.status().is_success(),
        "github callback should render the key-issued page, got {}",
        cb.status()
    );
    let page = cb.text().unwrap();
    assert!(
        page.contains("github:octotest"),
        "identity github:octotest must appear on the key page: {page}"
    );
    assert!(
        page.contains("user:github:octotest"),
        "group user:github:octotest must appear (role github:org/testorg must have bound)"
    );
    let api_key = issued_key_from_html(&page).expect("the key page carries the issued api_key");

    // The issued key AUTHENTICATES on the data plane (not 401).
    let chat = client
        .post(format!("{base}/v1/chat/completions"))
        .bearer_auth(&api_key)
        .json(&serde_json::json!({
            "model": "test-model",
            "messages": [{"role":"user","content":"hi"}],
        }))
        .send()
        .expect("chat with the issued key");
    assert_ne!(
        chat.status().as_u16(),
        401,
        "the self-scoped github key must authenticate on the data plane"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&work);
}
