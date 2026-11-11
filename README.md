# 取证证据接收系统（Evidence Intake）

应急响应场景下安全接收外包取证包的 Web 服务。分析员在接收页填写案件号与
**预期当前版本**（首次为 `0`），上传取证 ZIP 与独立 JSON 清单；服务端对
路径、条目类型、实际内容大小与 SHA-256 逐项核验，**全部通过才发布新版本**，
任何失败都不会改变当前版本，也不会在磁盘上暴露半包数据。

## 威胁模型与安全保证

取证包来自不可信外部人员，ZIP 与清单均为攻击面，服务端不信任任何声明字段。

### 路径与条目校验（`app/security.py`）

* 条目名仅允许 ASCII；拒绝非 ASCII 名称。
* 拒绝绝对路径（`/...`）、Windows 盘符（`C:...`）、反斜杠、空分量
  （`a//b`、首尾斜杠）、`.` 与 `..` 分量。
* 拒绝重复路径、文件/目录冲突（同时存在 `a` 与 `a/b`）。
* ZIP 仅接受普通文件：拒绝目录条目、Unix 软链接（`S_IFLNK`）、
  FIFO/设备等非常规文件、加密条目。
* 解压目标使用 `O_CREAT|O_EXCL` 打开，不会覆盖任何既有文件。

### 分块解压与 16 MiB 上限

* 64 KiB 分块流式读取，**按实际读出的字节**累计计数，达到
  `16 MiB + 1` 字节即中止；ZIP 头部声明的 `file_size` 不参与判断，
  因此高压缩比 zip-bomb（16 KiB 压缩 → 16 MiB+ 解压）同样被拒。
* 解压同时实时计算 SHA-256；`zipfile` 在流关闭时自动做 CRC-32 完整性校验。
* 解压中途失败会删除已落盘的半截文件。

### 清单与文件一一对应（`app/manifest.py` + `app/storage.py`）

独立 JSON 清单格式：

```json
{
  "files": [
    {"path": "report/notes.txt", "sha256": "<64位十六进制>"},
    {"path": "evidence/a.bin", "sha256": "<64位十六进制>"}
  ]
}
```

* 清单路径走与 ZIP 完全相同的相对路径规则，清单自身也不允许重复/冲突。
* 发布前要求清单与 ZIP 的路径集合**完全相等**，且每个文件实际计算的
  SHA-256 与清单声明一致；任一不符即整体拒绝。

### 原子发布与并发控制（`app/storage.py`）

* SQLite 开启 WAL；写事务一律 `BEGIN IMMEDIATE` 立即取锁，配合
  `busy_timeout` 与应用层短重试。
* **乐观版本号**：提交时携带预期当前版本，事务内重新读取比对。
  两个进程同时基于同一版本提交时，先拿锁的发布成功（版本 +1），
  后者读到新版本后返回 `409 Conflict`，当前版本不变。
* 文件先 `rename` 进不可变目录 `files/<case>/v<n>/`，再提交数据库事务；
  提交失败回收该目录。已发布版本目录永不改写，后续发布不影响旧版内容。
* 启动时通过 `flock` 互斥锁执行一次清理：清空暂存区/临时上传区，
  并删除“磁盘存在但数据库无记录”的孤儿版本目录——进程在任意时刻
  被杀死，重启后都不会暴露半包。

## 存储布局（`EVIDENCE_HOME`，默认 `./data`）

```
data/
├── evidence.db            # SQLite：cases / versions / files 三张表
├── files/<case_id>/v<n>/  # 已发布的不可变版本目录（附件原件）
├── staging/<uuid>/        # 每次接收的独立暂存区（结束即删）
└── tmp/                   # 上传临时文件（请求结束即删）
```

## 运行：Docker Compose（两个进程）

```bash
docker compose up --build
# 浏览器打开 http://localhost:8000
```

容器以 `gunicorn --workers 2 --worker-class uvicorn.workers.UvicornWorker`
启动，即**两个独立服务进程**共享同一命名卷 `/data` 与同一个 SQLite 数据库。
`/health` 返回的 `pid` 可用于确认请求确实落在不同进程上。

## 页面与 API

| 页面/接口 | 说明 |
| --- | --- |
| `GET /` | 首页：已发布案件/版本清单、样例下载入口、进入接收页的导航 |
| `GET /intake` | 证据接收页：案件号 + 预期当前版本 + ZIP + JSON 清单 |
| `POST /api/intake` | 接收主流程，成功 `201`，核验失败 `400`，版本冲突 `409` |
| `GET /api/cases` / `GET /api/cases/{id}` | 版本清单与案件详情 |
| `GET /api/cases/{id}/versions/{v}/files/{rel_path}` | 附件**强制 attachment 下载**，响应头带 `X-SHA256` |
| `GET /api/samples` 及 `.../{id}/bundle`、`.../{id}/manifest` | 演示样例 |

### 演示样例（首页可直接下载）

1. **正常样例** `benign`：结构与哈希全部正确，可成功发布；
2. **恶意样例** `malicious`：ZIP 内含软链接 `evil-link → /etc/passwd`
   与 `../pwned.txt` 路径穿越条目，解压阶段即被拒绝；
3. **篡改样例** `tampered`：ZIP 结构合法但清单 SHA-256 与实际内容不符，
   哈希核验阶段被拒绝。

建议演示案件号分别使用 `DEMO-BENIGN`、`DEMO-EVIL`、`DEMO-TAMPER`，
首次提交“预期当前版本”填 `0`。

## 本地开发与测试

```bash
pip install -r requirements.txt
pytest -q                      # 61 个测试，含跨进程并发与崩溃恢复
gunicorn app.main:app --workers 2 \
  --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

测试覆盖：路径/条目拒绝矩阵、16 MiB 实际字节边界、清单一一对应与哈希、
上传下载全链路、旧版本不可变、线程与**多进程**并发仅一份成功、
启动孤儿目录清理、失败后无暂存残留。
