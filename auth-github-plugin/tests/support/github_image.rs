// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

/// The fresh actual product image built by CI before this test binary runs.
pub(super) fn cdylib() -> PathBuf {
    let profile = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let path = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            profile.join(busbar_plugin_loader::plugin_library_filename(
                "busbar_auth_github_plugin",
            ))
        });
    assert!(
        path.is_absolute(),
        "BUSBAR_PLUGIN_CDYLIB must be an absolute actual product image path"
    );
    let built = std::fs::metadata(&path)
        .expect("build the actual github cdylib before conformance")
        .modified()
        .unwrap();
    fn check(path: &std::path::Path, built: std::time::SystemTime) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                check(&entry.path(), built);
            } else {
                assert!(
                    entry.metadata().unwrap().modified().unwrap() <= built,
                    "stale GitHub cdylib: rebuild after changing {}",
                    entry.path().display()
                );
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    for member in ["auth-github", "auth-github-plugin"] {
        check(&root.join(member).join("src"), built);
        assert!(
            std::fs::metadata(root.join(member).join("Cargo.toml"))
                .unwrap()
                .modified()
                .unwrap()
                <= built
        );
    }
    for file in ["Cargo.toml", "Cargo.lock", ".busbar-ref"] {
        assert!(
            std::fs::metadata(root.join(file))
                .unwrap()
                .modified()
                .unwrap()
                <= built,
            "rebuild after changing {file}"
        );
    }
    path
}
