use anyhow::Result;

pub fn upload_log(_log: &str, _stage: &str) -> Result<String> {
    // R装机：自动反馈已禁用，不上报到任何服务器。
    // 返回错误让调用方走手动日志流程（提示用户自行保存日志文件）。
    anyhow::bail!("自动反馈已禁用，请手动保存日志文件")
}
