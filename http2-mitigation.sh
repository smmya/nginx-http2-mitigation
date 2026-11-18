#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: run this script as root (sudo -i, then run it)." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required on the host." >&2
  exit 1
fi

exec python3 - "$@" <<'PY'
import base64
import datetime
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

STATE_ROOT = Path(os.environ.get("HTTP2_STATE_DIR", "/var/lib/nginx-http2-mitigation"))
MARKER_PREFIX = "HTTP2-MITIGATION:"
DOCKER = shutil.which("docker")


def run_cmd(args, timeout=45):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return 124, out, err + "\ncommand timed out"
    except Exception as e:
        return 127, "", str(e)


def b64e(value):
    return base64.b64encode(value.encode("utf-8", "surrogateescape")).decode("ascii")


def b64d(value):
    return base64.b64decode(value.encode("ascii")).decode("utf-8", "surrogateescape")


def atomic_write(path, data):
    path = Path(path)
    st = path.stat()
    fd, tmp = tempfile.mkstemp(prefix=".http2-mitigation-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            os.fchmod(f.fileno(), stat.S_IMODE(st.st_mode))
            try:
                os.fchown(f.fileno(), st.st_uid, st.st_gid)
            except PermissionError:
                pass
        try:
            shutil.copystat(path, tmp, follow_symlinks=False)
        except Exception:
            pass
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def parse_dump(stdout):
    files = {}
    current = None
    marker_re = re.compile(r"^# configuration file (.+):\s*$")
    for line in stdout.splitlines(keepends=True):
        m = marker_re.match(line.rstrip("\r\n"))
        if m:
            current = m.group(1).strip()
            files.setdefault(current, [])
        elif current is not None:
            files[current].append(line)
    return {k: "".join(v) for k, v in files.items()}


def get_version(binary, docker_name=None):
    prefix = [DOCKER, "exec", docker_name] if docker_name else []
    rc1, out1, err1 = run_cmd(prefix + [binary, "-v"])
    rc2, out2, err2 = run_cmd(prefix + [binary, "-V"])
    short = (out1 + err1).strip().replace("\n", " ")
    full = (out2 + err2).strip()
    if not short:
        short = "version unavailable"
    return short, full


def host_instance(name, product, binary, config):
    binary = str(binary)
    config = str(config)
    rc, out, err = run_cmd([binary, "-T", "-c", config], timeout=60)
    if rc != 0:
        print("[SKIP] {}: config dump failed: {}".format(name, (err or out).strip()[-500:]))
        return None
    files = parse_dump(out)
    if not files:
        print("[SKIP] {}: nginx -T returned no configuration file sections.".format(name))
        return None
    version, full = get_version(binary)
    iid = "host-" + re.sub(r"[^a-zA-Z0-9_.-]+", "-", name.lower())
    return {
        "id": iid, "product": product, "name": name, "kind": "host",
        "binary": binary, "config": config, "version": version,
        "build_info": full, "files": files, "mounts": [],
    }


def discover_mw():
    found = []
    server_dirs = []
    env_dir = os.environ.get("MW_SERVER_DIR")
    if env_dir:
        server_dirs.append(Path(env_dir))
    server_dirs.extend([Path("/www/server")])
    seen = set()
    for server_dir in server_dirs:
        try:
            server_dir = server_dir.resolve()
        except Exception:
            continue
        if str(server_dir) in seen:
            continue
        seen.add(str(server_dir))
        base = server_dir / "openresty"
        config = base / "nginx" / "conf" / "nginx.conf"
        candidates = [base / "bin" / "openresty", base / "nginx" / "sbin" / "nginx"]
        if not config.is_file():
            continue
        binary = next((p for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)
        if binary is None:
            print("[SKIP] MW-like OpenResty config found but binary missing: {}".format(config))
            continue
        product = "MW/OpenResty" if (server_dir / "mdserver-web" / "plugins" / "openresty" / "index.py").exists() else "OpenResty native (MW-compatible path)"
        item = host_instance("{} ({})".format(product, server_dir), product, binary, config)
        if item:
            found.append(item)
    return found


def container_mounts(inspect_data):
    result = []
    for m in inspect_data.get("Mounts", []) or []:
        dest = m.get("Destination")
        src = m.get("Source")
        if dest and src:
            result.append({"destination": dest.rstrip("/") or "/", "source": src,
                           "rw": bool(m.get("RW", False)), "type": m.get("Type", "")})
    return sorted(result, key=lambda x: len(x["destination"]), reverse=True)


def map_container_path(container_path, mounts):
    cp = Path(container_path)
    cstr = str(cp)
    for m in mounts:
        dest = m["destination"]
        if cstr == dest or cstr.startswith(dest.rstrip("/") + "/"):
            if not m["rw"]:
                return None, "mount is read-only"
            rel = cstr[len(dest):].lstrip("/")
            hp = Path(m["source"]) / rel if rel else Path(m["source"])
            try:
                hp = hp.resolve()
            except Exception:
                pass
            return hp, None
    return None, "file is not covered by a persistent Docker mount"


def discover_docker():
    found = []
    if not DOCKER:
        print("[INFO] Docker CLI not found; Docker-managed NPM/1Panel instances will not be scanned.")
        return found
    rc, out, err = run_cmd([DOCKER, "ps", "-q"], timeout=30)
    if rc != 0:
        print("[WARN] docker ps failed: {}".format(err.strip()[-300:]))
        return found
    ids = [x.strip() for x in out.splitlines() if x.strip()]
    for cid in ids:
        rc, jout, jerr = run_cmd([DOCKER, "inspect", cid], timeout=30)
        if rc != 0:
            continue
        try:
            info = json.loads(jout)[0]
        except Exception:
            continue
        name = (info.get("Name") or cid).lstrip("/")
        image = (info.get("Config", {}).get("Image") or "")
        labels = info.get("Config", {}).get("Labels") or {}
        mounts = container_mounts(info)
        hint = " ".join([name, image] + [str(k) + "=" + str(v) for k, v in labels.items()] +
                         [m["source"] + " " + m["destination"] for m in mounts]).lower()
        npm_hint = any(x in hint for x in ["nginx-proxy-manager", "npmplus", "npm-plus", "zoeyvid", "jc21"])
        openresty_hint = "openresty" in hint
        if not npm_hint and not openresty_hint:
            continue

        binaries = (["nginx", "openresty", "/usr/sbin/nginx", "/usr/local/openresty/nginx/sbin/nginx", "/usr/local/openresty/bin/openresty"]
                    if npm_hint else
                    ["openresty", "nginx", "/usr/local/openresty/bin/openresty", "/usr/local/openresty/nginx/sbin/nginx", "/usr/sbin/nginx"])
        selected = None
        dump_files = None
        dump_stderr = ""
        for binary in binaries:
            rc2, out2, err2 = run_cmd([DOCKER, "exec", name, binary, "-T"], timeout=60)
            if rc2 == 0:
                parsed = parse_dump(out2)
                if parsed:
                    selected = binary
                    dump_files = parsed
                    dump_stderr = err2
                    break
        if not selected:
            print("[SKIP] Docker candidate {} ({}): could not run nginx/openresty -T.".format(name, image))
            continue

        dump_text = "\n".join(dump_files.keys()) + "\n" + "\n".join(dump_files.values())
        if npm_hint or "/data/nginx/proxy_host/" in dump_text or "/data/nginx/default_host/" in dump_text:
            product = "NPM/NPMplus (Docker)"
        elif openresty_hint or "/www/sites/" in dump_text or "/www/conf.d/" in dump_text:
            if "1panel" in hint or "/apps/openresty/" in hint or "/1panel/" in hint or "/www/sites/" in dump_text:
                product = "1Panel/OpenResty (Docker)"
            else:
                product = "OpenResty Docker (auto-detected)"
        else:
            continue

        version, full = get_version(selected, name)
        found.append({
            "id": "docker-" + cid[:12], "product": product, "name": name,
            "kind": "docker", "container": name, "container_id": cid,
            "image": image, "binary": selected, "version": version,
            "build_info": full, "files": dump_files, "mounts": mounts,
        })
    return found


def strip_comment(line):
    quote = None
    escaped = False
    out = []
    for ch in line:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            out.append(ch)
            escaped = True
            continue
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out)


def nginx_code_only(line):
    """Return syntax outside comments and quoted strings for brace tracking."""
    quote = None
    escaped = False
    out = []
    for ch in line:
        if escaped:
            out.append(" ")
            escaped = False
            continue
        if ch == "\\":
            out.append(" ")
            escaped = True
            continue
        if quote:
            out.append(" ")
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '\"'):
            quote = ch
            out.append(" ")
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out)


def server_names_for_line(lines, target_index):
    depth = 0
    stack = []
    blocks = []
    for idx, line in enumerate(lines):
        code = nginx_code_only(line)
        for pos, ch in enumerate(code):
            if ch == "{":
                prefix = code[:pos].rstrip()
                if re.search(r"(?:^|\s)server\s*$", prefix):
                    stack.append({"depth": depth + 1, "start": idx})
                depth += 1
            elif ch == "}":
                while stack and stack[-1]["depth"] == depth:
                    item = stack.pop()
                    blocks.append((item["start"], idx))
                depth = max(0, depth - 1)
    candidates = [(start, end) for start, end in blocks if start <= target_index <= end]
    if not candidates:
        return []
    start, end = min(candidates, key=lambda x: x[1] - x[0])
    names = []
    for j in range(start, end + 1):
        m = re.match(r"^\s*server_name\s+([^;]+);", strip_comment(lines[j]))
        if m:
            names.extend(m.group(1).split())
    return names


def transform_line(line):
    if MARKER_PREFIX in line or not line.strip() or line.lstrip().startswith("#"):
        return None
    body = line.rstrip("\r\n")
    newline = line[len(body):]

    m = re.match(r"^([ \t]*)http2[ \t]+on[ \t]*;([ \t]*(?:#.*)?)$", body)
    if m:
        mid = uuid.uuid4().hex[:12]
        comment = m.group(2).strip()
        replacement = m.group(1) + "# " + MARKER_PREFIX + mid
        if comment:
            replacement += " " + comment
        return mid, "http2 on", replacement + newline

    # Also handle the uncommon but valid case where multiple directives share one line.
    m = re.match(r"^([ \t]*)(.+;[ \t]*)http2[ \t]+on[ \t]*;([ \t]*(?:#.*)?)$", body)
    if m:
        mid = uuid.uuid4().hex[:12]
        comment = m.group(3).strip()
        replacement = m.group(1) + m.group(2).rstrip() + " # " + MARKER_PREFIX + mid
        if comment:
            replacement += " " + comment
        return mid, "inline http2 on", replacement + newline

    m = re.match(r"^([ \t]*listen[ \t]+)([^;]*?)(;)([ \t]*(?:#.*)?)$", body)
    if m:
        params = m.group(2)
        tokens = re.split(r"[ \t]+", params.strip())
        if "http2" not in tokens:
            return None
        mid = uuid.uuid4().hex[:12]
        # Remove only the standalone http2 token; keep the listen directive and its other flags.
        new_params = re.sub(r"[ \t]+http2(?=[ \t]|$)", "", params, count=1)
        new_params = re.sub(r"[ \t]{2,}", " ", new_params).rstrip()
        comment = m.group(4).strip()
        replacement = m.group(1) + new_params + "; # " + MARKER_PREFIX + mid
        if comment:
            replacement += " " + comment
        return mid, "listen parameter http2", replacement + newline
    return None


def active_matches(text):
    lines = text.splitlines(keepends=True)
    matches = []
    for idx, line in enumerate(lines):
        result = transform_line(line)
        if result:
            mid, kind, replacement = result
            names = server_names_for_line(lines, idx)
            matches.append({"line_no": idx + 1, "kind": kind, "server_names": names,
                            "original": line, "replacement": replacement, "marker": MARKER_PREFIX + mid})
    return matches


def print_instances(instances):
    print("\n=== Detected web servers ===")
    if not instances:
        print("No supported MW/OpenResty, 1Panel OpenResty, NPM or NPMplus instance detected.")
        return
    for i, inst in enumerate(instances, 1):
        print("[{}] {} | {}".format(i, inst["product"], inst["name"]))
        print("    Version: {}".format(inst["version"]))
        if inst.get("image"):
            print("    Image: {}".format(inst["image"]))
        print("    Config files loaded: {}".format(len(inst["files"])))


def collect_file_targets(instances):
    targets = {}
    skipped = []
    for inst in instances:
        for conf_path, dump_text in inst["files"].items():
            if inst["kind"] == "host":
                host_path = Path(conf_path)
                reason = None
            else:
                host_path, reason = map_container_path(conf_path, inst["mounts"])
            if host_path is None:
                found = active_matches(dump_text)
                if found:
                    skipped.append({"instance": inst["name"], "path": conf_path,
                                    "reason": reason or "not persistently mounted", "matches": found})
                continue
            try:
                host_path = Path(host_path).resolve()
            except Exception:
                host_path = Path(host_path)
            if not host_path.is_file():
                found = active_matches(dump_text)
                if found:
                    skipped.append({"instance": inst["name"], "path": conf_path,
                                    "reason": "mapped host file does not exist: {}".format(host_path), "matches": found})
                continue
            key = str(host_path)
            if key not in targets:
                try:
                    raw = host_path.read_bytes()
                    text = raw.decode("utf-8", "surrogateescape")
                except Exception as e:
                    skipped.append({"instance": inst["name"], "path": conf_path,
                                    "reason": "cannot read mapped file: {}".format(e), "matches": []})
                    continue
                targets[key] = {"host_path": key, "content": text, "instances": [], "container_paths": {}}
            if inst["id"] not in targets[key]["instances"]:
                targets[key]["instances"].append(inst["id"])
            targets[key]["container_paths"][inst["id"]] = conf_path
    return targets, skipped


def instance_by_id(instances):
    return {x["id"]: x for x in instances}


def print_scan(instances, targets, skipped):
    print_instances(instances)
    print("\n=== Active HTTP/2 directives ===")
    total = 0
    for path, item in targets.items():
        matches = active_matches(item["content"])
        if not matches:
            continue
        for m in matches:
            total += 1
            site = ", ".join(m["server_names"]) if m["server_names"] else "site/context not inferred"
            print("[FOUND] {}:{} | {} | {}".format(path, m["line_no"], site, m["kind"]))
            print("        {}".format(m["original"].rstrip()))
    for item in skipped:
        for m in item["matches"]:
            total += 1
            site = ", ".join(m["server_names"]) if m["server_names"] else "site/context not inferred"
            print("[FOUND BUT NOT MODIFIABLE] {}:{} | {} | {}".format(item["path"], m["line_no"], site, m["kind"]))
            print("        Instance: {} | Reason: {}".format(item["instance"], item["reason"]))
    if total == 0:
        print("No active 'http2 on;' or 'listen ... http2;' directives found in loaded config files.")
    print("\nActive HTTP/2 directive count: {}".format(total))
    return total


def save_json(path, data):
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def make_plan(targets, instances, state_dir):
    changes = []
    file_plans = {}
    for host_path, item in targets.items():
        lines = item["content"].splitlines(keepends=True)
        out = []
        changed = False
        for idx, line in enumerate(lines):
            transformed = transform_line(line)
            if not transformed:
                out.append(line)
                continue
            mid, kind, replacement = transformed
            names = server_names_for_line(lines, idx)
            changes.append({
                "id": mid, "marker": MARKER_PREFIX + mid, "host_path": host_path,
                "container_paths": item["container_paths"], "instance_ids": item["instances"],
                "line_no": idx + 1, "kind": kind,
                "server_names": names, "original_b64": b64e(line),
                "replacement_b64": b64e(replacement),
            })
            out.append(replacement)
            changed = True
        if changed:
            backup_name = hashlib.sha256(host_path.encode()).hexdigest() + ".bak"
            backup_path = state_dir / "backups" / backup_name
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(host_path, backup_path)
            file_plans[host_path] = {"new_content": "".join(out).encode("utf-8", "surrogateescape"),
                                     "backup": str(backup_path)}
    return changes, file_plans


def test_instance(inst):
    if inst["kind"] == "host":
        args = [inst["binary"], "-t", "-c", inst["config"]]
    else:
        args = [DOCKER, "exec", inst["container"], inst["binary"], "-t"]
    rc, out, err = run_cmd(args, timeout=60)
    return rc == 0, (out + err).strip()


def restart_instance(inst):
    if inst["kind"] == "docker":
        rc, out, err = run_cmd([DOCKER, "restart", inst["container"]], timeout=90)
        if rc != 0:
            return False, (out + err).strip()
        rc2, out2, err2 = run_cmd([DOCKER, "inspect", "-f", "{{.State.Status}}", inst["container"]], timeout=20)
        status = out2.strip()
        return rc2 == 0 and status == "running", "docker restart: {}".format(status or (err2.strip() or "unknown"))

    if shutil.which("systemctl"):
        rc, out, err = run_cmd(["systemctl", "restart", "openresty"], timeout=90)
        if rc == 0:
            rc2, out2, err2 = run_cmd(["systemctl", "is-active", "openresty"], timeout=20)
            return rc2 == 0 and out2.strip() == "active", "systemctl status: {}".format(out2.strip() or err2.strip())
    initd = Path("/etc/init.d/openresty")
    if initd.is_file() and os.access(initd, os.X_OK):
        rc, out, err = run_cmd([str(initd), "restart"], timeout=90)
        return rc == 0, (out + err).strip()
    return False, "no supported openresty service manager found"


def restore_marked_lines(changes, strict=True):
    grouped = {}
    for ch in changes:
        grouped.setdefault(ch["host_path"], []).append(ch)
    snapshots = {}
    restored = []
    conflicts = []
    for path, entries in grouped.items():
        p = Path(path)
        if not p.is_file():
            conflicts.append((path, "file missing"))
            continue
        raw = p.read_bytes()
        snapshots[path] = raw
        text = raw.decode("utf-8", "surrogateescape")
        lines = text.splitlines(keepends=True)
        for ch in entries:
            expected = b64d(ch["replacement_b64"])
            original = b64d(ch["original_b64"])
            indexes = [i for i, line in enumerate(lines) if ch["marker"] in line]
            if len(indexes) != 1:
                conflicts.append((path, "marker {} found {} times".format(ch["id"], len(indexes))))
                continue
            idx = indexes[0]
            if lines[idx] != expected:
                conflicts.append((path, "modified line no longer matches our saved version (marker {})".format(ch["id"])))
                continue
            lines[idx] = original
            restored.append(ch)
        if any(ch in restored for ch in entries):
            atomic_write(p, "".join(lines).encode("utf-8", "surrogateescape"))
    return snapshots, restored, conflicts


def rollback_apply(changes):
    _, restored, conflicts = restore_marked_lines(changes, strict=False)
    return len(restored), conflicts


def latest_state():
    if not STATE_ROOT.is_dir():
        return None
    files = sorted(STATE_ROOT.glob("http2-state-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def load_state(path_arg=None):
    p = Path(path_arg) if path_arg else latest_state()
    if not p or not p.is_file():
        raise RuntimeError("No state file found. Pass the state JSON path printed by apply.")
    return p, json.loads(p.read_text(encoding="utf-8"))


def rediscover_for_state(state):
    current = discover_mw() + discover_docker()
    by_name = {}
    for inst in current:
        by_name[(inst["kind"], inst.get("container") or inst["name"])] = inst
    selected = []
    missing = []
    id_map = {}
    for saved in state.get("instances", []):
        key = (saved.get("kind"), saved.get("container") or saved.get("name"))
        inst = by_name.get(key)
        if inst:
            selected.append(inst)
            id_map[saved.get("id")] = inst.get("id")
        else:
            missing.append(key[1])
    return selected, missing, id_map


def command_scan(instances):
    targets, skipped = collect_file_targets(instances)
    print_scan(instances, targets, skipped)
    return 0


def command_apply(instances):
    targets, skipped = collect_file_targets(instances)
    print_scan(instances, targets, skipped)
    changes_count = sum(len(active_matches(x["content"])) for x in targets.values())
    if changes_count == 0:
        print("\nNothing to change. No restart performed.")
        return 0
    if skipped:
        skipped_matches = sum(len(x["matches"]) for x in skipped)
        if skipped_matches:
            print("\nWARNING: {} HTTP/2 directive(s) were found in files that are not persistently mounted; they will NOT be modified.".format(skipped_matches))

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    state_dir = STATE_ROOT
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    run_dir = state_dir / ("run-" + stamp)
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    state_path = state_dir / ("http2-state-" + stamp + ".json")

    changes, file_plans = make_plan(targets, instances, run_dir)
    affected_ids = sorted({iid for ch in changes for iid in ch["instance_ids"]})
    affected = [x for x in instances if x["id"] in affected_ids]
    state = {
        "schema": 1, "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "purpose": "Temporarily disable active HTTP/2 directives; restore only exact lines carrying this run's markers.",
        "instances": [{k: x.get(k) for k in ["id", "product", "name", "kind", "container", "container_id", "image", "binary", "config", "version"]} for x in affected],
        "changes": changes,
        "backups": {p: v["backup"] for p, v in file_plans.items()},
        "skipped": skipped,
    }
    # Persist the recovery information before changing any config file.
    save_json(state_path, state)

    applied_files = []
    try:
        for path, plan in file_plans.items():
            atomic_write(path, plan["new_content"])
            applied_files.append(path)
    except Exception as e:
        print("\nERROR: failed while writing config: {}".format(e))
        rollback_apply(changes)
        print("Rollback attempted. No services restarted.")
        return 1

    print("\n=== Config validation ===")
    failed = []
    for inst in affected:
        ok, detail = test_instance(inst)
        print("[{}] {}: {}".format("OK" if ok else "FAIL", inst["product"], inst["name"]))
        if detail:
            print("    {}".format(detail[-700:]))
        if not ok:
            failed.append(inst)
    if failed:
        restored_count, conflicts = rollback_apply(changes)
        print("\nERROR: at least one config test failed. Reverted {} modified directive(s); no service was restarted.".format(restored_count))
        for p, reason in conflicts:
            print("[ROLLBACK WARNING] {}: {}".format(p, reason))
        print("State and backups retained: {}".format(state_path))
        return 1

    print("\n=== Restart web servers ===")
    restart_failed = []
    for inst in affected:
        ok, detail = restart_instance(inst)
        print("[{}] {}: {}".format("OK" if ok else "FAIL", inst["product"], inst["name"]))
        if detail:
            print("    {}".format(detail[-500:]))
        if not ok:
            restart_failed.append(inst)

    print("\n=== Summary ===")
    print("Changed files: {}".format(len(file_plans)))
    print("Commented/adjusted directives: {}".format(len(changes)))
    print("Restart failures: {}".format(len(restart_failed)))
    print("State file: {}".format(state_path))
    print("Backups: {}".format(run_dir / "backups"))
    print("Restore later with: bash http2-mitigation.sh restore {}".format(state_path))
    return 0 if not restart_failed else 2


def command_restore(state_path_arg=None):
    state_path, state = load_state(state_path_arg)
    print("State file: {}".format(state_path))
    instances, missing, id_map = rediscover_for_state(state)
    if missing:
        print("[WARN] Could not rediscover these previously changed instances: {}".format(", ".join(missing)))
    if not state.get("changes"):
        print("No changes recorded in this state file.")
        return 0

    snapshots, restored, conflicts = restore_marked_lines(state["changes"])
    print("\n=== Restore result ===")
    print("Restored directives: {}".format(len(restored)))
    for path, reason in conflicts:
        print("[SKIP/CONFLICT] {}: {}".format(path, reason))
    if not restored:
        print("Nothing was restored. No restart performed.")
        return 0

    affected_ids = sorted({id_map[iid] for ch in restored for iid in ch.get("instance_ids", []) if iid in id_map})
    affected = [x for x in instances if x["id"] in affected_ids]
    print("\n=== Validate restored configuration ===")
    failed = []
    for inst in affected:
        ok, detail = test_instance(inst)
        print("[{}] {}: {}".format("OK" if ok else "FAIL", inst["product"], inst["name"]))
        if detail:
            print("    {}".format(detail[-700:]))
        if not ok:
            failed.append(inst)
    if failed:
        # Put the exact temporary-disable lines back if restoring made any server config invalid.
        for path, raw in snapshots.items():
            atomic_write(path, raw)
        print("\nERROR: restored config validation failed. Reverted the restore operation; HTTP/2 remains disabled on recorded lines.")
        return 1

    print("\n=== Restart web servers ===")
    restart_failed = []
    for inst in affected:
        ok, detail = restart_instance(inst)
        print("[{}] {}: {}".format("OK" if ok else "FAIL", inst["product"], inst["name"]))
        if detail:
            print("    {}".format(detail[-500:]))
        if not ok:
            restart_failed.append(inst)
    print("\nRestore complete. Restored: {} | Restart failures: {}".format(len(restored), len(restart_failed)))
    print("The state file and backups were retained: {}".format(state_path))
    return 0 if not restart_failed else 2


def main():
    mode = sys.argv[1].lower() if len(sys.argv) > 1 else "scan"
    if mode in ("-h", "--help", "help"):
        print("Usage: bash http2-mitigation.sh [scan|apply|restore [state-json]]")
        print("  scan    Read-only scan (default)")
        print("  apply   Backup, disable active HTTP/2 directives, validate, restart affected servers")
        print("  restore Restore only lines carrying this script's exact markers, validate, restart")
        return 0
    if mode not in ("scan", "apply", "restore"):
        print("Unknown mode: {}".format(mode))
        print("Usage: bash http2-mitigation.sh [scan|apply|restore [state-json]]")
        return 2
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    lock_path = STATE_ROOT / "run.lock"
    with open(lock_path, "w") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        if mode == "restore":
            return command_restore(sys.argv[2] if len(sys.argv) > 2 else None)
        instances = discover_mw() + discover_docker()
        if not instances:
            print("No supported web server instance was detected.")
            print("MW default path: /www/server/openresty")
            print("Docker: running containers with NPM/NPMplus or OpenResty image/name")
            return 0
        if mode == "scan":
            return command_scan(instances)
        return command_apply(instances)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BlockingIOError:
        print("ERROR: another HTTP/2 mitigation script is already running.", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print("ERROR: {}".format(e), file=sys.stderr)
        sys.exit(1)
PY