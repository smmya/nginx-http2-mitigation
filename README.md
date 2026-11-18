# HTTP/2 Mitigation for Nginx / OpenResty Panels

A small host-side Bash/Python utility to inspect and temporarily disable active HTTP/2 directives in supported Nginx/OpenResty deployments managed by:

- **MW / mdserver-web** with host-installed OpenResty
- **1Panel** with its Docker-managed OpenResty
- **Nginx Proxy Manager (NPM)** in Docker
- **NPMplus** in Docker

The script can discover multiple supported instances on the same host (for example, MW OpenResty plus an NPM container).

> **Important:** This is a temporary mitigation helper, not a replacement for installing vendor security updates. Disabling HTTP/2 only mitigates attack paths that require HTTP/2; it does not fix other Nginx/OpenResty vulnerabilities or Linux kernel vulnerabilities. Re-enable HTTP/2 only after confirming that the relevant server build contains the required security fixes.

## Requirements

- Linux host
- Run as `root`
- Python 3 on the host
- Docker CLI and permission to access the Docker daemon for Docker-managed instances
- Supported Docker containers must have their active Nginx configuration files on writable persistent bind mounts or Docker volumes. Files only present in the container image are detected but deliberately not modified.

No third-party Python packages are required. The script has passed shell/Python syntax checks and focused directive-transformation tests; real-world integration testing against every panel/image variant is still recommended.

## Quick start

Download the script:

```bash
curl -fsSLo /root/http2-mitigation.sh \
  https://raw.githubusercontent.com/smmya/nginx-http2-mitigation/main/http2-mitigation.sh
chmod 700 /root/http2-mitigation.sh
```


### 1. Read-only scan

```bash
bash /root/http2-mitigation.sh scan
```

`scan` does not modify Nginx/OpenResty configuration files or restart services. It reports detected instances, Nginx/OpenResty versions, loaded configuration files, and active HTTP/2 directives it can locate. On first run it creates the root-only state directory and lock file under `/var/lib/nginx-http2-mitigation/`.

### 2. Apply temporary mitigation

```bash
bash /root/http2-mitigation.sh apply
```

The script:

1. Discovers supported MW/OpenResty and Docker-managed NPM, NPMplus, and OpenResty instances.
2. Uses each instance's `nginx -T` / `openresty -T` output to inspect configuration files actually loaded by the server.
3. Finds active `http2 on;` directives and `listen ... http2;` parameters.
4. Creates backups and a state file before modifying configuration.
5. Comments `http2 on;` and removes only the standalone `http2` token from `listen` directives, preserving the rest of each directive.
6. Runs the relevant `nginx -t` / `openresty -t` configuration test.
7. Restarts only the affected OpenResty service or Docker container if validation succeeds.

Files that are not covered by writable persistent Docker mounts are reported as **FOUND BUT NOT MODIFIABLE** and are not changed. This avoids edits that would disappear when a container is recreated.

### 3. Restore HTTP/2 later

Restore the most recent run:

```bash
bash /root/http2-mitigation.sh restore
```

Or restore a specific run using the exact state-file path printed by `apply`:

```bash
bash /root/http2-mitigation.sh restore \
  /var/lib/nginx-http2-mitigation/http2-state-YYYYMMDD-HHMMSS.json
```

Restore only replaces lines that still contain this run's unique marker and exactly match the script's saved replacement. If a marked line was subsequently edited, the script reports a conflict and leaves that line unchanged.

## State and backups

By default, state and backups are stored under:

```text
/var/lib/nginx-http2-mitigation/
```

The directory is restricted to root (`0700`). Each apply run creates a timestamped state JSON and a backup directory. Keep these files until the mitigation is no longer needed and the restore has been completed or intentionally abandoned.

You can change the state directory by setting `HTTP2_STATE_DIR` consistently for both `apply` and `restore`:

```bash
HTTP2_STATE_DIR=/root/http2-state bash /root/http2-mitigation.sh apply
HTTP2_STATE_DIR=/root/http2-state bash /root/http2-mitigation.sh restore
```

## Supported directive forms

The script handles both common forms:

```nginx
listen 443 ssl http2;
```

and:

```nginx
listen 443 ssl;
http2 on;
```

It does not attempt to rewrite arbitrary custom syntax or directives split across unusual multi-line constructs.

## Operational notes and limitations

- `scan` is the recommended first step. Review its output before running `apply`.
- The script operates on active files reported by the server's configuration dump; it does not recursively rewrite every `.conf` file on disk.
- A Docker config file is modified only when its container path maps to a writable persistent mount on the host.
- Docker-managed web servers are restarted as containers. MW/OpenResty is restarted through `systemctl` or its init script.
- If configuration validation fails, the script attempts to restore the modified lines and does not restart the affected service.
- If a restart fails after validation, the script reports the failure and retains the state and backups for manual recovery.
- Review custom Nginx/OpenResty configurations and application dependencies before disabling HTTP/2. Applications that require HTTP/2 (for example, some gRPC deployments) may be affected.
- This project does not determine whether a specific CVE is exploitable on a host. Check the relevant vendor advisories and installed package/image patch status.

## License

No license has been assigned yet. Do not assume permission to redistribute or modify this project until a license is added.