use anyhow::{Context, Result};
use base64::Engine;

const FEEDBACK_URL: &str = "https://api.cloud-pe.cn/v1/feedback";

pub fn upload_log(log: &str, stage: &str) -> Result<String> {
    // R装机：暂不上报到外部服务器，直接返回空 ticket
    let _ = (log, stage);
    Ok(String::new())
}

fn session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!(
        "{:x}-{:x}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}
