// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin-SIDE live end-to-end for the GitHub login plugin — the mirror of `auth-oidc-plugin`'s

use std::io::Write as _;

/// The WireMock base URL a CI service container exposes (e.g. `http://127.0.0.1:8080`). Absent ⇒ skip.
fn wiremock_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_WIREMOCK_URL") {
        Ok(u) if !u.trim().is_empty() => Some(u.trim().trim_end_matches('/').to_string()),
        _ => None,
    }
}

/// The busbar checkout the live e2e builds the REAL `busbar` and `busbar-plugin-pack` binaries from:
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
    let target = std::path::PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR")
            .expect("CARGO_TARGET_DIR must name the assigned native target directory"),
    );
    assert!(
        target.is_absolute() && target.is_dir(),
        "CARGO_TARGET_DIR must be an existing absolute assigned target: {}",
        target.display()
    );

    let metadata = std::process::Command::new("cargo")
        .args([
            "+1.98.0",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .current_dir(&root)
        .output()
        .expect("read the selected busbar checkout's package targets");
    assert!(
        metadata.status.success(),
        "locked busbar metadata failed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("Cargo metadata JSON");
    let mut owners = Vec::new();
    for package in metadata["packages"].as_array().expect("metadata packages") {
        for binary in package["targets"].as_array().expect("package targets") {
            if binary["name"].as_str() == Some("busbar-plugin-pack")
                && binary["kind"]
                    .as_array()
                    .expect("target kinds")
                    .iter()
                    .any(|kind| kind.as_str() == Some("bin"))
            {
                owners.push((package, binary));
            }
        }
    }
    assert_eq!(
        owners.len(),
        1,
        "the selected busbar checkout must declare exactly one busbar-plugin-pack binary owner"
    );
    let (owner, binary) = owners[0];
    let mut pack_args = vec![
        "+1.98.0".to_owned(),
        "build".to_owned(),
        "--locked".to_owned(),
        "-j2".to_owned(),
        "--release".to_owned(),
        "-p".to_owned(),
        owner["name"]
            .as_str()
            .expect("owner package name")
            .to_owned(),
        "--bin".to_owned(),
        "busbar-plugin-pack".to_owned(),
    ];
    if let Some(required) = binary.get("required-features") {
        let features = required
            .as_array()
            .expect("required feature names")
            .iter()
            .map(|feature| feature.as_str().expect("required feature name"))
            .collect::<Vec<_>>();
        if !features.is_empty() {
            pack_args.extend(["--features".to_owned(), features.join(",")]);
        }
    }
    let busbar_args = [
        "+1.98.0",
        "build",
        "--locked",
        "-j2",
        "--release",
        "--manifest-path",
        "dist/default/Cargo.toml",
        "--bin",
        "busbar",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    for args in [busbar_args, pack_args] {
        let status = std::process::Command::new("cargo")
            .args(&args)
            .current_dir(&root)
            .status()
            .expect("run cargo build for busbar / busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    (
        target.join("release/busbar"),
        target.join("release/busbar-plugin-pack"),
    )
}

#[path = "support/github_image.rs"]
mod github_image;

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
            env!("CARGO_PKG_VERSION"),
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

/// The busbar process, killed and reaped when it drops: a failed assertion never leaks it (or its
struct Busbar(std::process::Child);

impl Drop for Busbar {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The test's scratch directory, removed when it drops.
struct Scratch(std::path::PathBuf);

impl std::ops::Deref for Scratch {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn reserve_port() -> std::net::TcpListener {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap()
}

/// Register the GitHub stub mappings on WireMock over its admin API (equivalent to the JSON files under
fn register_wiremock_stubs(client: &reqwest::blocking::Client, base: &str) {
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

    let _ = client.post(format!("{base}/__admin/mappings/reset")).send();
    let mappings = [
        serde_json::json!({
            "request": { "method": "POST", "urlPath": "/login/oauth/access_token",
                "headers": { "Accept": {"equalTo":"application/json"},
                    "Content-Type": {"contains":"application/x-www-form-urlencoded"} },
                "bodyPatterns": [
                    {"matches":"(^|.*&)client_id=Iv1.e2eclient(&.*|$)"},
                    {"matches":"(^|.*&)client_secret=e2e-secret(&.*|$)"},
                    {"matches":"(^|.*&)code=e2e-code(&.*|$)"},
                    {"matches":"(^|.*&)code_verifier=[A-Za-z0-9_-]+(&.*|$)"}
                ] },
            "response": { "status": 200, "headers": { "Content-Type": "application/json" },
                "jsonBody": { "access_token": "gho_test", "token_type": "bearer", "scope": "" } }
        }),
        serde_json::json!({
            "request": { "method": "GET", "urlPath": "/user", "headers": { "Authorization": {"equalTo":"Bearer gho_test"}, "Accept": {"equalTo":"application/vnd.github+json"} } },
            "response": { "status": 200, "headers": { "Content-Type": "application/json" },
                "jsonBody": { "login": "octotest", "id": 12345, "name": "Octo Test" } }
        }),
        serde_json::json!({
            "request": { "method": "GET", "urlPath": "/user/orgs", "headers": { "Authorization": {"equalTo":"Bearer gho_test"}, "Accept": {"equalTo":"application/vnd.github+json"} }, "queryParameters": {"per_page":{"equalTo":"100"}} },
            "response": { "status": 200, "headers": { "Content-Type": "application/json" },
                "jsonBody": [ { "login": "testorg" } ] }
        }),
        serde_json::json!({
            "request": {"method":"POST", "urlPath":"/v1/messages"},
            "response": {"status":200, "headers":{"Content-Type":"application/json"},
                "jsonBody":{"id":"msg_e2e", "type":"message", "role":"assistant", "model":"test-model",
                    "content":[{"type":"text","text":"authenticated"}], "stop_reason":"end_turn", "stop_sequence":null,
                    "usage":{"input_tokens":1,"output_tokens":1}}}
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
fn cookie_fields(cookie_value: &str) -> serde_json::Value {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cookie_value)
        .expect("cookie is base64url");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("cookie is JSON");
    v
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

/// THE plugin-side proof: a REAL busbar boot drives the github GET flow; the plugin executes the real
#[test]
fn github_get_flow_mints_key_via_core_executed_hops() {
    let Some(wm) = wiremock_url() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI is set but BUSBAR_TEST_WIREMOCK_URL is unset: the plugin-ci `service: wiremock` \
             arm did not run, so the github live e2e cannot (refusing to pass without running)"
        );
        eprintln!(
            "skip: BUSBAR_TEST_WIREMOCK_URL unset — github live e2e needs the WireMock service \
             container (set by the plugin-ci `service: wiremock` arm). Skipping (local, no docker)."
        );
        return;
    };
    let so_path = github_image::cdylib();
    let (busbar_bin, pack_bin) = build_real_binaries();

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    register_wiremock_stubs(&client, &wm);

    let work = Scratch(std::env::temp_dir().join(format!(
        "busbar-github-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    pack_github(
        &pack_bin,
        &so_path,
        &plugins_dir.join("busbar-auth-github.tar.gz"),
    );

    let data_listener = reserve_port();
    let admin_listener = reserve_port();
    let data_port = data_listener.local_addr().unwrap().port();
    let admin_port = admin_listener.local_addr().unwrap().port();
    assert_ne!(data_port, admin_port);
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

    std::fs::write(
        &providers,
        format!("mock:\n  protocol: anthropic\n  base_url: \"{wm}\"\n"),
    )
    .unwrap();

    let config = work.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:{data_port}\"\n\
             admin_listen: \"127.0.0.1:{admin_port}\"\n\
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

    drop((data_listener, admin_listener));
    let mut child = Busbar(
        std::process::Command::new(&busbar_bin)
            .env("BUSBAR_CONFIG", &config)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("MOCK_KEY", "unused")
            .env("BUSBAR_GH_CLIENT_SECRET", "e2e-secret")
            .env("BUSBAR_ADMIN_TOKEN", "e2e-admin-token")
            .env("BUSBAR_STATE_FILE", "")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn busbar with identity-providers.github"),
    );
    let base = format!("http://127.0.0.1:{data_port}");
    wait_for_health(&client, &format!("{base}/healthz"), &mut child.0);

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
    let login_cookie = cookie_fields(&cookie_value);
    let state = login_cookie["state"].as_str().expect("cookie state");

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

    let journal: serde_json::Value = client
        .get(format!("{wm}/__admin/requests"))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    let token_requests: Vec<_> = journal["requests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["request"]["url"] == "/login/oauth/access_token")
        .collect();
    assert_eq!(token_requests.len(), 1);
    let body = token_requests[0]["request"]["body"].as_str().unwrap();
    let form_url = reqwest::Url::parse(&format!("http://fixture.invalid/?{body}")).unwrap();
    let form: std::collections::HashMap<_, _> = form_url.query_pairs().into_owned().collect();
    assert_eq!(
        form.get("client_id").map(String::as_str),
        Some("Iv1.e2eclient")
    );
    assert_eq!(
        form.get("client_secret").map(String::as_str),
        Some("e2e-secret")
    );
    assert_eq!(form.get("code").map(String::as_str), Some("e2e-code"));
    assert_eq!(
        form.get("code_verifier").map(String::as_str),
        login_cookie["code_verifier"].as_str()
    );
    assert!(
        page.contains("github:octotest"),
        "identity github:octotest must appear on the key page: {page}"
    );
    assert!(
        page.contains("user:github:octotest"),
        "group user:github:octotest must appear (role github:org/testorg must have bound)"
    );
    let api_key = issued_key_from_html(&page).expect("the key page carries the issued api_key");

    let leaf = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/api/v1/admin/groups/user:github:octotest"
        ))
        .header("x-admin-token", "e2e-admin-token")
        .send()
        .expect("GET the provisioned leaf group");
    assert!(
        leaf.status().is_success(),
        "the user:github:octotest leaf group exists, got {}",
        leaf.status()
    );
    let leaf: serde_json::Value = leaf.json().expect("the group view is JSON");
    assert_eq!(
        leaf["parent"].as_str(),
        Some("eng-team"),
        "role github:org/testorg must bind the sign-in to eng-team: {leaf}"
    );

    let chat = client
        .post(format!("{base}/v1/chat/completions"))
        .bearer_auth(&api_key)
        .json(&serde_json::json!({
            "model": "test-model",
            "messages": [{"role":"user","content":"hi"}],
        }))
        .send()
        .expect("chat with the issued key");
    assert_eq!(
        chat.status().as_u16(),
        200,
        "the issued key reaches the configured model"
    );
    let chat: serde_json::Value = chat.json().expect("chat response JSON");
    assert_eq!(chat["choices"][0]["message"]["content"], "authenticated");
}
