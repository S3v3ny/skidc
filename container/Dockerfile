# syntax=docker/dockerfile:1
#
# Skidc worker container — the per-project execution environment.
#
# The dispatcher execs agent CLIs (claude / codex) INSIDE this container during an
# authorized security assessment. Kali base + offensive tooling + a persistent
# headless Chromium driven over the DevTools Protocol (CDP).
#
# Requires BuildKit (default on Docker Desktop). The `# syntax` line above enables
# the heredoc `COPY <<'SCRIPT'` used for the chrome-start helper. If you build with
# DOCKER_BUILDKIT=0 it will fail — export DOCKER_BUILDKIT=1 first.
#
# Build:  docker build -t skidc-worker:latest -f container/Dockerfile container

FROM --platform=amd64 kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai
ENV PYTHONUNBUFFERED=1
ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
# Let `node -e "require('puppeteer-core')"` resolve the globally-installed module
# regardless of which dir the agent runs from. Covers both Debian/Kali global prefixes.
ENV NODE_PATH=/usr/local/lib/node_modules:/usr/lib/node_modules

# ------------------------------------------------------------------
# 1. Kali apt mirror fix + apt tooling, SPLIT INTO 4 CACHEABLE LAYERS
# ------------------------------------------------------------------
# The base image ships sources in DEB822 (/etc/apt/sources.list.d/kali.sources) and
# may also have legacy /etc/apt/sources.list. Layer 1 rewrites the URI to Aliyun's Kali
# mirror over http — keep it http so apt can run before ca-certificates is installed. The
# sed runs ONCE; the rewritten sources persist in the image filesystem, so Layers 2-4 only
# need apt-get update + install.
#
# WHY FOUR LAYERS: seclists is a single ~1.7 GB .deb and the Aliyun mirror frequently times
# out mid-download. In one combined RUN, that timeout fails the whole layer and discards the
# already-downloaded kali-linux-headless (~5 GB). Splitting by size/role lets BuildKit cache
# each layer independently — a seclists timeout only reruns Layer 2 (starting in seconds)
# instead of re-pulling the metapackage. Each layer self-cleans (clean + rm lists) so the
# intermediate layers stay lean. Cost: apt-get update runs 4× (package indices are small).
#
# Most tools are in Kali's repos, so we avoid pinning release versions for
# nuclei / naabu / dirsearch / gitleaks (no 404-on-wrong-tag build breaks, no version drift).
# katana and dalfox are NOT in Kali repos and are fetched from GitHub in step 4.
# kali-linux-headless is the official metapackage (~1300 pkgs / 500+ CLI tools): nmap, sqlmap,
# nikto, hydra, netexec + base utils (curl/wget/git/unzip/tmux/sudo/python3-pip/
# default-jre-headless). The explicit packages are those the metapackage does NOT pull in.
# ffuf/gobuster/dirb/wfuzz ARE in the metapackage but are listed explicitly so they survive a
# metapackage drop. Trade-off: ~16-20 GB image, ~25-40 min first build (cached after).

# Layer 1: mirror fix + base system (kali-linux-headless + small utilities). Largest layer,
# but the mirror is reliable for these; cached after the first successful build.
RUN find /etc/apt/sources.list.d/ -type f \( -name '*.list' -o -name '*.sources' \) -exec sed -i \
        -e 's|mirror\.wane\.kr|mirrors.aliyun.com|g' \
        -e 's|http://http\.kali\.org|http://mirrors.aliyun.com|g' \
        {} + \
    && [ -f /etc/apt/sources.list ] && sed -i \
        -e 's|mirror\.wane\.kr|mirrors.aliyun.com|g' \
        -e 's|http://http\.kali\.org|http://mirrors.aliyun.com|g' \
        /etc/apt/sources.list || true \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        kali-linux-headless \
        jq yq ripgrep fd-find \
        nodejs npm \
        ncat dnsutils iputils-ping \
        bsdextrautils sshpass rlwrap \
    && ln -sf /usr/bin/fdfind /usr/local/bin/fd \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Layer 2: seclists (~1.7 GB — the frequent timeout offender). Retried once in-layer so a
# single stalled connection resumes from apt's partial download cache before the layer fails.
# No --fix-missing: we want a genuine failure to surface (and rerun ONLY this layer on the
# next build) rather than silently produce an image with no wordlists.
RUN apt-get update \
    && (apt-get install -y --no-install-recommends seclists \
        || (sleep 10 && apt-get install -y --no-install-recommends seclists)) \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Layer 3: web / recon tooling.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ffuf gobuster dirb wfuzz \
        nuclei naabu dirsearch gitleaks \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Layer 4: remaining tooling + chromium runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        chisel pwncat \
        enum4linux-ng krb5-user \
        bloodyad coercer \
        adb \
        chromium fonts-liberation \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------
# 2. Agent CLIs + puppeteer-core (Node CDP client, no bundled browser)
#    Versions are PINNED for reproducible builds — the CLIs' loop/flag
#    semantics matter to the dispatcher. Bump deliberately, not implicitly.
# ------------------------------------------------------------------
RUN npm install -g \
        @anthropic-ai/claude-code@2.1.98 \
        @openai/codex@0.118.0 \
        puppeteer-core \
    && npm cache clean --force

# ------------------------------------------------------------------
# 3. pip tools (pwntools import name is `pwn`; bloodyAD/coercer installed via
#    apt above to avoid "Cannot uninstall cryptography" conflict with Debian)
# ------------------------------------------------------------------
RUN pip3 install --break-system-packages --no-cache-dir \
        pwntools pymongo

# ------------------------------------------------------------------
# 4. Tools NOT in Kali repos — fetched via gh-proxy.com (Chinese GitHub
#    CDN proxy) to avoid slow/blocked direct GitHub access from China.
#    git clone is replaced with zip download + unzip (proxy doesn't support
#    git protocol). NOTE: the proxy may go down; if builds fail on this
#    step, replace gh-proxy.com with another mirror or remove the prefix
#    to fall back to direct GitHub.
# ------------------------------------------------------------------
# 4a. GitHub tools via gh-proxy.com — one RUN per tool so Docker caches
#     each independently. wget --tries=3 --retry-connrefused handles
#     intermittent proxy failures without rebuilding other tools.
# ------------------------------------------------------------------
ENV GH=https://gh-proxy.com/https://github.com
RUN mkdir -p /home/kali/tools /home/kali/.local /home/kali/.config/nuclei
# cloudfox (cloud enumeration)
RUN wget --tries=3 --retry-connrefused -qO /tmp/cloudfox.zip \
        "$GH/BishopFox/cloudfox/releases/latest/download/cloudfox-linux-amd64.zip" \
    && unzip -oq /tmp/cloudfox.zip -d /tmp/cfx \
    && { mv /tmp/cfx/cloudfox/cloudfox /usr/local/bin/cloudfox 2>/dev/null || mv /tmp/cfx/cloudfox /usr/local/bin/cloudfox; } \
    && chmod +x /usr/local/bin/cloudfox \
    && rm -rf /tmp/cloudfox.zip /tmp/cfx
# kerbrute (Kerberos brute-force)
RUN wget --tries=3 --retry-connrefused -qO /usr/local/bin/kerbrute \
        "$GH/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" \
    && chmod +x /usr/local/bin/kerbrute
# ysoserial (Java deserialization)
RUN wget --tries=3 --retry-connrefused -qO /home/kali/tools/ysoserial.jar \
        "$GH/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" \
    && printf '#!/bin/bash\nexec java -jar /home/kali/tools/ysoserial.jar "$@"\n' > /usr/local/bin/ysoserial \
    && chmod +x /usr/local/bin/ysoserial
# jwt_tool (JWT testing)
RUN wget --tries=3 --retry-connrefused -qO /tmp/jwt_tool.zip \
        "$GH/ticarpi/jwt_tool/archive/refs/heads/master.zip" \
    && unzip -oq /tmp/jwt_tool.zip -d /home/kali/tools/ \
    && mv /home/kali/tools/jwt_tool-master /home/kali/tools/jwt_tool \
    && pip3 install --break-system-packages --no-cache-dir -r /home/kali/tools/jwt_tool/requirements.txt \
    && printf '#!/bin/bash\nexec python3 /home/kali/tools/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool \
    && rm -f /tmp/jwt_tool.zip
# jdwp-shellifier (Java remote debug)
RUN wget --tries=3 --retry-connrefused -qO /tmp/jdwp.zip \
        "$GH/IOActive/jdwp-shellifier/archive/refs/heads/master.zip" \
    && unzip -oq /tmp/jdwp.zip -d /home/kali/tools/ \
    && mv /home/kali/tools/jdwp-shellifier-master /home/kali/tools/jdwp-shellifier \
    && rm -f /tmp/jdwp.zip
# katana (URL crawler)
RUN wget --tries=3 --retry-connrefused --max-redirect=10 -qO /tmp/katana.zip \
        "$GH/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip" \
    && unzip -oq /tmp/katana.zip -d /tmp/katana \
    && mv /tmp/katana/katana /usr/local/bin/katana \
    && chmod +x /usr/local/bin/katana \
    && rm -rf /tmp/katana.zip /tmp/katana
# dalfox (XSS scanner)
RUN wget --tries=3 --retry-connrefused --max-redirect=10 -qO /tmp/dalfox.tar.gz \
        "https://gh-proxy.com/https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-amd64.tar.gz" \
    && tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin/ \
    && mv /usr/local/bin/dalfox-linux-amd64 /usr/local/bin/dalfox \
    && chmod +x /usr/local/bin/dalfox \
    && rm -f /tmp/dalfox.tar.gz

# ------------------------------------------------------------------
# 4b. nuclei-templates — Gitee mirror (faster in China than GitHub).
#     Independent layer so failures here don't block other tools.
# ------------------------------------------------------------------
RUN git clone --depth=1 https://gitee.com/xqdd/nuclei-templates.git \
        /home/kali/.local/nuclei-templates \
    && printf 'disable-update-check: true\n' > /home/kali/.config/nuclei/config.yaml

# ------------------------------------------------------------------
# 4c. Knowledge bases — offline reference corpora the agent greps at
#     test time (methodology, payloads, logic-flaw case libraries).
#     Cloned shallow (--depth=1) via gh-proxy. Split across RUN layers
#     so one slow/failed repo doesn't invalidate the others' cache.
#     (gh-proxy DOES proxy `git clone` over https — verified — despite the
#     note in step 4 that the zip path is used for release binaries.)
#     Paths are referenced from AGENTS.md ("Knowledge bases" section). NOTE:
#     this adds ~1 GB (HackTricks alone is ~770 MB); drop repos here to slim.
# ------------------------------------------------------------------
# ONE repo per RUN, each retried once after a 5 s pause. gh-proxy.com drops the TLS
# connection mid-transfer on large repos ("GnuTLS recv error / early EOF"); when several
# clones shared a layer, one drop discarded the repos that had already cloned. Isolating each
# means a drop only reruns that repo's layer, and the in-layer retry usually rides out a
# transient stall without a rebuild. --depth=1 is already set; a failed clone leaves no
# partial dir (git cleans up), so the retry starts fresh.
# General web/pentest methodology + payloads
RUN mkdir -p /home/kali/knowledges && cd /home/kali/knowledges \
    && (git clone --depth=1 "$GH/swisskyrepo/PayloadsAllTheThings.git" \
        || (sleep 5 && git clone --depth=1 "$GH/swisskyrepo/PayloadsAllTheThings.git"))
RUN cd /home/kali/knowledges \
    && (git clone --depth=1 "$GH/swisskyrepo/InternalAllTheThings.git" \
        || (sleep 5 && git clone --depth=1 "$GH/swisskyrepo/InternalAllTheThings.git"))
# Awesome-POC / HackTricks / wooyun-legacy: fetched as archive zips, NOT git clone.
# gh-proxy's git smart-http transport drops mid-pack on these (TLS recv error / early EOF)
# and a broken pack can't resume — it restarts the whole transfer. A zip is one HTTP file,
# so wget --tries=3 --retry-connrefused resumes instead of restarting. These are read-only
# grep corpora; dropping .git costs nothing and shrinks them. (Same path jwt_tool uses in 4a.)
RUN cd /home/kali/knowledges \
    && wget --tries=3 --retry-connrefused -qO /tmp/apoc.zip \
        "$GH/Threekiii/Awesome-POC/archive/refs/heads/master.zip" \
    && unzip -oq /tmp/apoc.zip && mv Awesome-POC-master Awesome-POC \
    && rm -f /tmp/apoc.zip
# HackTricks is large (~770 MB) — isolate it in its own layer
RUN cd /home/kali/knowledges \
    && wget --tries=3 --retry-connrefused -qO /tmp/ht.zip \
        "$GH/HackTricks-wiki/hacktricks/archive/refs/heads/master.zip" \
    && unzip -oq /tmp/ht.zip && mv hacktricks-master hacktricks \
    && rm -f /tmp/ht.zip
# Business-logic / logic-flaw focused corpora — each in its own layer
RUN cd /home/kali/knowledges \
    && wget --tries=3 --retry-connrefused -qO /tmp/wy.zip \
        "$GH/tanweai/wooyun-legacy/archive/refs/heads/main.zip" \
    && unzip -oq /tmp/wy.zip && mv wooyun-legacy-main wooyun-legacy \
    && rm -f /tmp/wy.zip
RUN cd /home/kali/knowledges \
    && (git clone --depth=1 "$GH/Az0x7/vulnerability-Checklist.git" \
        || (sleep 5 && git clone --depth=1 "$GH/Az0x7/vulnerability-Checklist.git"))
RUN cd /home/kali/knowledges \
    && (git clone --depth=1 "$GH/OWASP/www-project-top-10-for-business-logic-abuse.git" owasp-bla-top10 \
        || (sleep 5 && git clone --depth=1 "$GH/OWASP/www-project-top-10-for-business-logic-abuse.git" owasp-bla-top10))
RUN cd /home/kali/knowledges \
    && (git clone --depth=1 "$GH/yaklang/hack-skills.git" \
        || (sleep 5 && git clone --depth=1 "$GH/yaklang/hack-skills.git"))

# ------------------------------------------------------------------
# 5. chrome-start helper — persistent headless Chromium with CDP.
#
#  - Uses --remote-debugging-port=0: the OS assigns a free port, so multiple
#    project containers on the host network never collide on a fixed 9222.
#  - Chromium writes the chosen port to <profile>/DevToolsActivePort; we copy its
#    first line to <profile>/cdp-port for the agent to read.
#  - setsid + nohup detaches Chromium from the `docker exec` session so it keeps
#    running across tasks (the profile persists cookies / localStorage / login).
#  - --disable-dev-shm-usage: containers usually have a tiny /dev/shm; without this
#    Chromium crashes on non-trivial pages.
# ------------------------------------------------------------------
COPY <<'SCRIPT' /usr/local/bin/chrome-start
#!/bin/bash
PROFILE=/home/kali/chrome-profile
PORTFILE="$PROFILE/DevToolsActivePort"
mkdir -p "$PROFILE"

# Already up? reuse it.
if [ -f "$PORTFILE" ]; then
  P=$(head -1 "$PORTFILE")
  if [ -n "$P" ] && curl -fs "http://127.0.0.1:$P/json/version" >/dev/null 2>&1; then
    echo "$P" > "$PROFILE/cdp-port"
    echo "Chrome already running on CDP port $P"
    exit 0
  fi
fi

rm -f "$PORTFILE"
setsid nohup chromium \
  --headless=new \
  --no-sandbox \
  --disable-gpu \
  --disable-dev-shm-usage \
  --remote-debugging-port=0 \
  --remote-debugging-address=127.0.0.1 \
  --user-data-dir="$PROFILE" \
  --disable-background-networking \
  --disable-default-apps \
  --disable-extensions \
  --disable-sync \
  --no-first-run \
  "$@" >/dev/null 2>&1 </dev/null &

for _ in $(seq 1 40); do
  [ -f "$PORTFILE" ] && break
  sleep 0.5
done

if [ ! -f "$PORTFILE" ]; then
  echo "ERROR: Chromium failed to start (no DevToolsActivePort after 20s)" >&2
  exit 1
fi

P=$(head -1 "$PORTFILE")
echo "$P" > "$PROFILE/cdp-port"
echo "Chrome CDP ready at 127.0.0.1:$P (port also in $PROFILE/cdp-port)"
SCRIPT

RUN chmod +x /usr/local/bin/chrome-start

# ------------------------------------------------------------------
# 6. Non-root user + ownership. Claude Code refuses --dangerously-skip-permissions
#    as root. The home directory itself must be owned by kali so the CLI can create
#    ~/.claude/ (session state, debug logs). chown /home/kali directly instead of
#    recursive chown on the whole tree — knowledge bases and tools stay root-owned
#    (755 = readable) and don't get duplicated into a new layer.
# ------------------------------------------------------------------
RUN useradd -m -s /bin/bash kali \
    && echo "kali ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
    && mkdir -p /home/kali/workspace /home/kali/chrome-profile /home/kali/.claude \
    && chown kali:kali /home/kali /home/kali/workspace /home/kali/chrome-profile /home/kali/.claude /home/kali/.config /home/kali/.local

USER kali
WORKDIR /home/kali/workspace

COPY --chown=kali:kali ./AGENTS.md /home/kali/workspace/AGENTS.md
COPY --chown=kali:kali ./AGENTS.md /home/kali/workspace/CLAUDE.md
