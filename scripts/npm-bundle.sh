#!/usr/bin/env bash
# npm-bundle.sh — 构建 DSH npm 包装 + 供应链 integrity 清单（投毒对账）
# 输出: npm/dsh-bashpy-migrate/npm-integrity.json（tarball sha512 + lockfile pin）
# 消费: skill 侧 gk_plugin_manifest.py 对 url:npm: 插件强制 config.integrity 对账；
#       发布后 npm view <pkg>@<ver> dist.integrity 与本地 hash 对比可检测 registry 投毒。
# 原则: tarball sha512 是内容确定性核心（不依赖 registry）；lockfile 为尽力 pin，
#       peer 依赖（@deepseek-ai/dsh-tools）由宿主 DSH 提供，解析失败不阻塞。
set -euo pipefail
cd "$(dirname "$0")/../npm/dsh-bashpy-migrate"

npm install --package-lock-only --ignore-scripts --no-audit \
  >/dev/null 2>&1 || echo "warn: peer 解析失败（宿主 DSH 提供依赖，不影响 tarball 确定性）" >&2
npm pack --json > /tmp/pack.json

python3 - /tmp/pack.json <<'PY'
import hashlib, json, os, sys
pack = json.load(open(sys.argv[1]))[0]
tgz = pack["filename"]
h = hashlib.sha512(open(tgz, "rb").read()).hexdigest()
out = {
    "npmName": "@zthl-harness/dsh-bashpy-migrate",
    "version": pack["version"],
    "tarball": tgz,
    "integrity": "sha512-" + h,
    "fileCount": pack.get("fileCount"),
    "unpackedSize": pack.get("unpackedSize"),
    "lockfile": "package-lock.json" if os.path.exists("package-lock.json") else None,
    "note": "skill 加载器对 url:npm: 强制 config.integrity；npm view <pkg>@<ver> dist.integrity 与本地对账检测 registry 投毒",
}
json.dump(out, open("npm-integrity.json", "w"), indent=2, ensure_ascii=False)
print("npm integrity:", out["integrity"])
PY
