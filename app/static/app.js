/* 前端逻辑：首页清单/详情、样例下载、接收页提交。 */

function formatSize(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

async function fetchJson(url, options) {
  const resp = await fetch(url, options);
  let body = null;
  try {
    body = await resp.json();
  } catch (_) {
    /* 非 JSON 响应 */
  }
  if (!resp.ok) {
    const detail = body && body.detail ? body.detail : `HTTP ${resp.status}`;
    const err = new Error(detail);
    err.status = resp.status;
    throw err;
  }
  return body;
}

function downloadUrl(caseId, version, relPath) {
  return `/api/cases/${encodeURIComponent(caseId)}/versions/${version}/files/${relPath
    .split("/")
    .map(encodeURIComponent)
    .join("/")}`;
}

/* ---------------- 首页 ---------------- */

async function renderHome() {
  const tbody = document.querySelector("#cases-table tbody");
  const empty = document.getElementById("cases-empty");
  const cases = await fetchJson("/api/cases");

  tbody.innerHTML = "";
  empty.hidden = cases.length > 0;
  for (const c of cases) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${c.case_id}</strong></td>
      <td>v${c.current_version}</td>
      <td>${c.file_count}</td>
      <td>${formatSize(c.total_size)}</td>
      <td>${c.updated_at}</td>
      <td><a class="btn btn-small" href="#case=${encodeURIComponent(c.case_id)}">查看版本</a></td>`;
    tbody.appendChild(tr);
  }

  const hash = window.location.hash;
  if (hash.startsWith("#case=")) {
    await renderDetail(decodeURIComponent(hash.slice(6)));
  }

  const samples = await fetchJson("/api/samples");
  const wrap = document.getElementById("samples");
  wrap.innerHTML = "";
  for (const s of samples) {
    const div = document.createElement("div");
    div.className = "sample";
    div.innerHTML = `
      <h3>${s.title}</h3>
      <p>${s.description}</p>
      <div class="actions">
        <a class="btn btn-small" href="${s.zip_url}">下载 ZIP</a>
        <a class="btn btn-small btn-ghost" href="${s.manifest_url}">下载 JSON 清单</a>
      </div>`;
    wrap.appendChild(div);
  }
}

async function renderDetail(caseId) {
  const card = document.getElementById("detail-card");
  const body = document.getElementById("detail-body");
  document.getElementById("detail-title").textContent = `案件 ${caseId} 的已发布版本`;
  card.hidden = false;

  const detail = await fetchJson(`/api/cases/${encodeURIComponent(caseId)}`);
  body.innerHTML = `
    <p class="hint">
      当前版本 v${detail.current_version}，共 ${detail.versions.length} 个已发布版本。
      每个版本内容不可变，附件仅支持下载。
    </p>`;

  for (const v of detail.versions) {
    const block = document.createElement("div");
    block.className = "version-block";
    const items = v.files
      .map(
        (f) => `
        <li>
          <span class="file-path">${f.rel_path}
            <span class="meta">(${formatSize(f.size)}) ${f.sha256.slice(0, 16)}…</span>
          </span>
          <a class="btn btn-small btn-ghost"
             href="${downloadUrl(caseId, v.version, f.rel_path)}">下载附件</a>
        </li>`
      )
      .join("");
    block.innerHTML = `
      <h3>版本 v${v.version}
        <span class="meta">· ${v.created_at} · ${v.file_count} 个文件 ·
        ${formatSize(v.total_size)}</span>
      </h3>
      <ul class="file-list">${items}</ul>`;
    body.appendChild(block);
  }
  card.scrollIntoView({ behavior: "smooth" });
}

/* ---------------- 接收页 ---------------- */

function renderIntake() {
  const form = document.getElementById("intake-form");
  const result = document.getElementById("result");
  const btn = document.getElementById("submit-btn");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    result.hidden = false;
    result.className = "result";
    result.textContent = "正在上传并分块核验，请稍候……";
    btn.disabled = true;

    const data = new FormData(form);
    try {
      const body = await fetchJson("/api/intake", { method: "POST", body: data });
      result.className = "result ok";
      result.textContent =
        `✅ ${body.message}\n` +
        `案件号：${body.case_id}\n新版本：v${body.version}\n附件数：${body.file_count}`;
      form.reset();
      form.expected_version.value = body.version;
    } catch (err) {
      result.className = "result err";
      const prefix = err.status === 409 ? "⛔ 版本冲突" : "⛔ 接收被拒绝";
      result.textContent = `${prefix}（HTTP ${err.status || "?"}）\n${err.message}\n\n当前版本未发生任何变化。`;
    } finally {
      btn.disabled = false;
    }
  });
}

/* ---------------- 启动 ---------------- */

document.addEventListener("DOMContentLoaded", () => {
  if (document.body.dataset.page === "intake") {
    renderIntake();
  } else {
    renderHome().catch((err) => {
      const empty = document.getElementById("cases-empty");
      empty.hidden = false;
      empty.textContent = `加载失败：${err.message}`;
    });
  }
});
