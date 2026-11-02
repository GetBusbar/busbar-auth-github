// SPDX-License-Identifier: Apache-2.0
//! GitHub diagnostic assertions record formatted tracing output on the calling thread.
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(crate) struct GithubDiagnostics {
    bytes: Arc<Mutex<Vec<u8>>>,
    level: tracing::Level,
}
impl Default for GithubDiagnostics {
    fn default() -> Self {
        Self {
            bytes: Arc::default(),
            level: tracing::Level::WARN,
        }
    }
}
impl GithubDiagnostics {
    pub(crate) fn capturing_debug() -> Self {
        Self {
            level: tracing::Level::DEBUG,
            ..Self::default()
        }
    }
    pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        let writer = self.clone();
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(self.level)
            .with_writer(move || writer.clone())
            .finish()
    }
    pub(crate) fn messages(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.bytes.lock().unwrap())
            .lines()
            .map(str::to_owned)
            .collect()
    }
    pub(crate) fn contains(&self, text: &str) -> bool {
        self.messages().iter().any(|line| line.contains(text))
    }
}
impl Write for GithubDiagnostics {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
