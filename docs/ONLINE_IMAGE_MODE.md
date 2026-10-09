# PE 在线下载安装镜像（macOS 式网络安装）

本分支（`feat/pe-http-install`，基于 NORMAL-EX/LetRecovery fork）在上游基础上新增：
**PE 端自行从 HTTP 服务端下载安装镜像**，桌面端不再需要预置/暂存镜像文件。
流程对标 macOS 互联网恢复：进 PE → 联网 → 下载镜像 → 校验 → 释放安装。

> 许可证：本项目（含新增代码）沿用上游 **PolyForm Noncommercial 1.0.0**，
> 仅允许非商业场景使用，禁止商用、禁止收费分发。

## 使用方法

1. 准备一台 HTTP 文件服务器，把 `.wim`/`.esd` 镜像放上去（例如
   `http://192.168.1.10:8080/images/win11.wim`）。
   可选：在服务端记录镜像的 SHA-256。
2. 桌面端 → 高级选项 → 勾选 **「PE 在线下载安装镜像（http:// 镜像 URL）」**，
   填写镜像 URL。
3. 按正常流程选择目标分区并开始安装。桌面端将不再要求选择本地镜像文件，
   也不再执行镜像校验/复制阶段。
4. 重启进入 PE 后，安装程序会自动：
   - 拉起 PE 网络（有线 DHCP；若桌面端配置了 Wi-Fi 负载则尝试无线），
   - 核对交接描述文件与配置一致，
   - 以 `Range` 断点续传下载镜像到数据分区 `pe_online_image/`，
   - 校验 SHA-256（若配置了），
   - 继续常规的释放/引导流程。

## 实现要点

- `lr-core/src/pe_http_fetch.rs`（新增，纯标准库，零依赖）：
  手写 HTTP/1.1 客户端，支持 `Range` 续传、重定向（≤5 跳）、分块传输、
  失败重试（3 次，校验失败不重试）、下载后 SHA-256 校验。
  11 个单元测试（`cargo test -p lr-core pe_http_fetch`，Linux 可跑）。
- 交接配置新增 `ImageSourceUrl` / `ImageSourceLength` / `ImageSourceSha256`
  三个认证字段（桌面端 `install_config.rs` 序列化 → PE 端 `config.rs` 解析），
  URL 模式下强制 `PeNetworkEnabled=true`。
- `handoff_manifest.rs` 新增 `ArtifactRole::OnlineImageDescriptor`：
  桌面端把 `online_image.json`（URL/哈希/长度）写入数据分区并纳入 manifest 签名，
  满足"安装交接至少一个认证镜像源"的结构校验；PE 端下载前核对描述文件与 INI 一致。
- PE 端 `app.rs`：`ImageSourceUrl` 非空时走下载分支（网络预检在 handoff
  消费之前完成，避免后台网络线程竞态）；`pe_network.rs` 新增同步
  `ensure_network_blocking()`。
- 桌面端执行器跳过 `VerifySourceImage` / `CopySourceImage` 阶段；
  `start_intent` 在 URL 模式下不再要求本地镜像，但校验 URL 合法性
 （必须 `http://` 开头、无控制字符、长度 ≤2048）。

## v1 限制

- 仅支持 `http://`，不支持 `https://`（WinPE 内 TLS 栈不确定，后续版本再加）。
- UI 暂不采集镜像 SHA-256/长度（可在后续版本的高级选项中补充输入框）；
  不填则下载后跳过哈希校验——**生产使用强烈建议提供 SHA-256**。
- 桌面端仍需能进 PE（需要写 BCD 一次性引导项），"在线"指的是镜像获取环节。
