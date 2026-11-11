"""端到端 API 测试：上传、发布、下载、版本清单、失败不改变当前版。"""

from __future__ import annotations

import hashlib

from tests.conftest import make_manifest, make_zip


def _post(client, case_id, expected, entries, *, manifest_override=None, raw_zip=None,
          manifest_raw=None):
    z = raw_zip if raw_zip is not None else make_zip(entries)
    m = manifest_raw if manifest_raw is not None else make_manifest(
        entries, overrides=manifest_override
    )
    return client.post(
        "/api/intake",
        data={"case_id": case_id, "expected_version": str(expected)},
        files={
            "zip_file": ("bundle.zip", z, "application/zip"),
            "manifest_file": ("manifest.json", m, "application/json"),
        },
    )


def test_full_publish_and_download_flow(client, settings):
    entries = [
        ("report/notes.txt", b"first version notes\n"),
        ("evidence/a.bin", b"\xde\xad\xbe\xef"),
    ]
    r = _post(client, "CASE-001", 0, entries)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["version"] == 1
    assert body["file_count"] == 2

    # 首页清单可见。
    cases = client.get("/api/cases").json()
    assert len(cases) == 1
    assert cases[0]["case_id"] == "CASE-001"
    assert cases[0]["current_version"] == 1

    # 附件可下载，字节与哈希一致，且为 attachment 下载。
    dl = client.get("/api/cases/CASE-001/versions/1/files/report/notes.txt")
    assert dl.status_code == 200
    assert dl.content == b"first version notes\n"
    assert "attachment" in dl.headers["content-disposition"]
    assert dl.headers["x-sha256"] == hashlib.sha256(b"first version notes\n").hexdigest()

    # 不存在的附件 404。
    assert client.get("/api/cases/CASE-001/versions/1/files/missing").status_code == 404


def test_second_version_and_immutability(client, settings):
    e1 = [("f.txt", b"v1 content")]
    assert _post(client, "CASE-002", 0, e1).status_code == 201

    e2 = [("f.txt", b"v2 content"), ("g.txt", b"more")]
    r = _post(client, "CASE-002", 1, e2)
    assert r.status_code == 201
    assert r.json()["version"] == 2

    # 旧版本内容保持不变。
    old = client.get("/api/cases/CASE-002/versions/1/files/f.txt")
    new = client.get("/api/cases/CASE-002/versions/2/files/f.txt")
    assert old.content == b"v1 content"
    assert new.content == b"v2 content"

    detail = client.get("/api/cases/CASE-002").json()
    assert detail["current_version"] == 2
    assert [v["version"] for v in detail["versions"]] == [1, 2]
    assert [v["file_count"] for v in detail["versions"]] == [1, 2]


def test_stale_expected_version_conflicts_and_current_unchanged(client):
    e1 = [("f.txt", b"v1")]
    assert _post(client, "CASE-003", 0, e1).status_code == 201

    # 另一提交仍以为当前是 0 → 409，当前版本保持 v1。
    r = _post(client, "CASE-003", 0, [("f.txt", b"late")])
    assert r.status_code == 409
    assert "版本冲突" in r.json()["detail"]

    cases = client.get("/api/cases").json()
    case = next(c for c in cases if c["case_id"] == "CASE-003")
    assert case["current_version"] == 1
    assert client.get("/api/cases/CASE-003/versions/2/files/f.txt").status_code == 404


def test_malicious_zip_symlink_and_traversal_rejected(client, settings):
    raw = make_zip([("ok.txt", b"ok")], symlinks={"link": "/etc/passwd"})
    r = _post(client, "CASE-EVIL", 0, [("ok.txt", b"ok")], raw_zip=raw)
    assert r.status_code == 400
    assert "软链接" in r.json()["detail"]

    # 含路径穿越的包。
    raw2 = make_zip([("../escape", b"x"), ("ok.txt", b"ok")])
    r2 = _post(client, "CASE-EVIL", 0, [("ok.txt", b"ok")], raw_zip=raw2)
    assert r2.status_code == 400
    assert r2.json()["detail"]

    # 案件根本未创建。
    assert client.get("/api/cases/CASE-EVIL").status_code == 404
    assert client.get("/api/cases").json() == []


def test_hash_mismatch_rejected(client, settings):
    entries = [("img.bin", b"actual bytes")]
    r = _post(
        client,
        "CASE-TAMPER",
        0,
        entries,
        manifest_override={"img.bin": "0" * 64},
    )
    assert r.status_code == 400
    assert "SHA-256" in r.json()["detail"]
    assert client.get("/api/cases/CASE-TAMPER").status_code == 404


def test_manifest_zip_mismatch_rejected(client):
    # 清单多一个文件、ZIP 少一个；反之亦然。
    zip_entries = [("a.txt", b"a")]
    manifest_entries = [("a.txt", b"a"), ("b.txt", b"b")]
    r = _post(
        client,
        "CASE-MAP",
        0,
        zip_entries,
        manifest_raw=make_manifest(manifest_entries),
    )
    assert r.status_code == 400
    assert "一一对应" in r.json()["detail"]

    r2 = _post(
        client,
        "CASE-MAP",
        0,
        [("a.txt", b"a"), ("b.txt", b"b")],
        manifest_raw=make_manifest([("a.txt", b"a")]),
    )
    assert r2.status_code == 400
    assert "一一对应" in r2.json()["detail"]
    assert client.get("/api/cases").json() == []


def test_bad_case_id_rejected(client):
    r = _post(client, "../evil", 0, [("a.txt", b"a")])
    assert r.status_code == 400


def test_negative_expected_version_rejected(client):
    r = _post(client, "CASE-N", -1, [("a.txt", b"a")])
    assert r.status_code in (400, 422)


def test_oversize_actual_bytes_rejected(client, settings):
    big = b"x" * (settings.max_total_bytes + 1)
    r = _post(client, "CASE-BIG", 0, [("big.bin", big)])
    assert r.status_code == 400
    assert "上限" in r.json()["detail"]
    assert client.get("/api/cases").json() == []


def test_sample_endpoints(client):
    samples = client.get("/api/samples").json()
    ids = {s["id"] for s in samples}
    assert ids == {"benign", "malicious", "tampered"}

    bundle = client.get("/api/samples/benign/bundle")
    manifest = client.get("/api/samples/benign/manifest")
    assert bundle.status_code == 200 and manifest.status_code == 200
    assert "attachment" in bundle.headers["content-disposition"]

    # 用正常样例实际发布一次。
    r = client.post(
        "/api/intake",
        data={"case_id": "DEMO-BENIGN", "expected_version": "0"},
        files={
            "zip_file": ("benign.zip", bundle.content, "application/zip"),
            "manifest_file": ("manifest.json", manifest.content, "application/json"),
        },
    )
    assert r.status_code == 201, r.text

    # 恶意样例必须被拒。
    evil_zip = client.get("/api/samples/malicious/bundle").content
    evil_manifest = client.get("/api/samples/malicious/manifest").content
    r2 = client.post(
        "/api/intake",
        data={"case_id": "DEMO-EVIL", "expected_version": "0"},
        files={
            "zip_file": ("evil.zip", evil_zip, "application/zip"),
            "manifest_file": ("manifest.json", evil_manifest, "application/json"),
        },
    )
    assert r2.status_code == 400

    # 篡改样例必须被拒。
    t_zip = client.get("/api/samples/tampered/bundle").content
    t_manifest = client.get("/api/samples/tampered/manifest").content
    r3 = client.post(
        "/api/intake",
        data={"case_id": "DEMO-TAMPER", "expected_version": "0"},
        files={
            "zip_file": ("t.zip", t_zip, "application/zip"),
            "manifest_file": ("manifest.json", t_manifest, "application/json"),
        },
    )
    assert r3.status_code == 400


def test_pages_served(client):
    assert client.get("/").status_code == 200
    assert client.get("/intake").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_health_exposes_pid(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert isinstance(body["pid"], int)


def test_no_half_pack_left_on_failure(client, settings):
    # 恶意包失败后，暂存区与临时区均无残留，files 下没有该案件目录。
    raw = make_zip([("ok.txt", b"ok")], symlinks={"link": "/x"})
    r = _post(client, "CASE-LEFTOVER", 0, [("ok.txt", b"ok")], raw_zip=raw)
    assert r.status_code == 400

    assert not any(settings.staging_dir.iterdir())
    assert not any(settings.tmp_dir.iterdir())
    assert not (settings.files_dir / "CASE-LEFTOVER").exists()
