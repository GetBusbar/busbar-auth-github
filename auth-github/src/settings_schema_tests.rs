// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signed schema and the real lifecycle validator agree on representative settings.

use super::*;
use serde_json::{json, Value};

fn check(cases: &[(Value, bool)]) {
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("valid settings schema");
    assert_eq!(STATEMENT.settings_schema.ptr, SETTINGS_SCHEMA.as_ptr());
    assert_eq!(STATEMENT.settings_schema.len, SETTINGS_SCHEMA.len());
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    for (settings, accepted) in cases {
        let bytes = serde_json::to_vec(settings).expect("settings JSON");
        assert_eq!(
            validator.is_valid(settings),
            *accepted,
            "schema: {settings}"
        );
        assert_eq!(
            <Github as Life>::validate(&bytes).is_ok(),
            *accepted,
            "lifecycle: {settings}"
        );
    }
}

#[test]
fn settings_schema_matches_github_lifecycle() {
    let minimal = json!({"client_id":"client","api_base":"https://api.github.com","token_base":"https://github.com"});
    check(&[
        (minimal.clone(), true),
        (json!({}), false),
        (json!([]), false),
    ]);
    for (key, value, accepted) in [
        ("client_id", json!(""), false),
        ("client_id", json!(" "), true),
        ("scopes", json!([]), false),
        ("scopes", json!(["user"]), true),
        ("scopes", json!([42]), false),
        ("fetch_orgs", json!(false), true),
        ("fetch_orgs", Value::Null, false),
        ("ca_cert_pem", Value::Null, true),
        ("ca_cert_pem", json!("not PEM"), false),
        ("client_secret", json!("secret"), false),
        ("unknown", Value::Null, false),
    ] {
        let mut settings = minimal.clone();
        settings[key] = value;
        check(&[(settings, accepted)]);
    }
    for key in ["client_id", "api_base", "token_base"] {
        let mut settings = minimal.clone();
        settings.as_object_mut().unwrap().remove(key);
        check(&[(settings, false)]);
    }
    let mut login_only = minimal.clone();
    login_only["fetch_orgs"] = json!(false);
    login_only["scopes"] = json!([]);
    check(&[(login_only, true)]);
    let cfg: crate::GitHubConfig = serde_json::from_value(minimal).unwrap();
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let props = &schema["properties"];
    assert_eq!(props["scopes"]["default"], json!(cfg.scopes));
    assert_eq!(props["authorize_base"]["default"], cfg.authorize_base);
    assert_eq!(props["fetch_orgs"]["default"], cfg.fetch_orgs);
}

#[test]
fn immutable_identity_declares_the_host_transition_gate() {
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    assert_eq!(schema["x-busbar-principal-format"], "github-v2");
    assert_eq!(
        schema["x-busbar-principal-domain-fields"],
        json!([{"pointer":"/api_base","required":true}])
    );
    for base in [
        "https://u:p@api.github.com",
        "https://api.github.com?x=1",
        "https://api.github.com#fragment",
    ] {
        let settings =
            json!({"client_id":"client","api_base":base,"token_base":"https://github.com"});
        assert!(<Github as Life>::validate(&serde_json::to_vec(&settings).unwrap()).is_err());
    }
}
