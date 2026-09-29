"""C / C++ memory-safety rules."""

import textwrap

import pytest

from armorix.finding import Severity
from armorix.scanner import scan

C, H, M = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM


def run(tmp_path, name, code):
    (tmp_path / name).write_text(textwrap.dedent(code))
    return sorted((f.rule_id, f.severity) for f in scan(tmp_path, deps=False).findings)


VULNERABLE = [
    # the two samples shown in the website's taint lab
    ("pkt.c", """
        void process_packet(const char *input) {
            char buf[64];
            size_t len = strlen(input);
            strcpy(buf, input);
            log_info("pkt=%s len=%zu", buf, len);
        }""", [("ARX-C-BOF", H)]),
    ("session.cpp", """
        void cleanup_session(Session* s) {
            audit_log(s->id);
            delete s;
            metrics.inc("closed");
            s->last_ping = now();
        }""", [("ARX-C-UAF", H)]),
    # tainted copy with trace argv → strcpy
    ("main.c", """
        int main(int argc, char **argv) {
            char name[32];
            char *arg = argv[1];
            strcpy(name, arg);
            return 0;
        }""", [("ARX-C-BOF", C)]),
    ("lit.c", 'void f(void) { char b[4]; strcpy(b, "overflow"); }', [("ARX-C-BOF", C)]),
    ("mem.c", "void f(const char *s) { char b[16]; memcpy(b, s, 64); }", [("ARX-C-BOF", C)]),
    ("net.c", """
        void h(int fd) {
            char len_buf[8]; char out[128];
            read(fd, len_buf, sizeof len_buf);
            int n = atoi(len_buf);
            memcpy(out, len_buf, n);
        }""", [("ARX-C-BOF", H)]),
    ("gets.c", "void f(void) { char b[80]; gets(b); }", [("ARX-C-GETS", C)]),
    ("scan.c", 'void f(void) { char u[32]; scanf("%s", u); }', [("ARX-C-BOF", H)]),
    ("dfree.c", "void f(void) { char *p = malloc(8); free(p); free(p); }", [("ARX-C-DFREE", H)]),
    ("fmt.c", """
        void f(void) {
            char line[256];
            fgets(line, sizeof line, stdin);
            printf(line);
        }""", [("ARX-C-FMT", C)]),
    ("alloc.c", """
        void f(int fd) {
            unsigned n;
            recv(fd, &n, 4, 0);
            char *p = malloc(n * 16);
        }""", [("ARX-C-INTOVF", H)]),
    ("cmd.c", """
        int main(int argc, char **argv) {
            char cmd[256];
            snprintf(cmd, sizeof cmd, "ping -c 1 %s", argv[1]);
            return system(cmd);
        }""", [("ARX-C-CMDI", C)]),
]

SAFE = [
    ("ok1.c", 'void f(const char *s) { char b[64]; snprintf(b, sizeof(b), "%s", s); }'),
    ("ok2.c", 'void f(void) { char b[16]; strcpy(b, "short"); }'),
    ("ok3.c", "void f(const char *s) { char b[16]; memcpy(b, s, sizeof(b)); strncpy(b, s, 15); }"),
    ("ok4.c", "void f(void) { char *p = malloc(8); use(p); free(p); p = NULL; }"),
    ("ok5.c", """
        int f(char *p) {
            if (!ok(p)) { free(p); return -1; }
            return use(p);
        }"""),
    ("ok6.c", "void f(void) { char *p = malloc(4); free(p); p = malloc(4); p[0] = 1; free(p); }"),
    ("ok7.c", 'void f(int x) { printf("%d\\n", x); fprintf(stderr, "err %s", strerror(x)); }'),
    ("ok8.c", 'void f(void) { char u[32]; scanf("%31s", u); system("ls -l"); }'),
    ("ok9.c", "void log_msg(const char *fmt) { vprintf(fmt, ap); printf(fmt); }"),
    ("ok10.cpp", "void f() { auto* s = new Session(); use(s); delete s; s = nullptr; }"),
    ("ok11.c", 'void f(int n) { char b[64]; sprintf(b, "%d items", n); }'),
    ("ok12.c", """
        void zfree(void *ptr) {
        #ifdef A
            release(ptr);
        #elif B
            free(ptr);
        #else
            void *real = (char*)ptr - 8;
            free(real);
        #endif
        }"""),
    ("ok13.c", "void f(char *p, int e) { if (e) free(p); else use(p); }"),
    ("ok14.c", "void f(char **v) { int i; for (i = 0; i < 4; i++) { char *p = v[i]; free(p); } char *p = get(); use(p); }"),
]


@pytest.mark.parametrize("name, code, expected", VULNERABLE)
def test_detects(tmp_path, name, code, expected):
    assert run(tmp_path, name, code) == sorted(expected)


@pytest.mark.parametrize("name, code", SAFE)
def test_no_false_positive(tmp_path, name, code):
    assert run(tmp_path, name, code) == []


def test_trace_from_argv(tmp_path):
    (tmp_path / "m.c").write_text("int main(int argc, char **argv) {\n  char n[8];\n  char *a = argv[1];\n  strcpy(n, a);\n}\n")
    (f,) = scan(tmp_path, deps=False).findings
    assert [s.line for s in f.trace] == [3, 4] and f.data["source"] == "a"


def test_uaf_trace_points_to_free(tmp_path):
    (tmp_path / "u.cpp").write_text("void f(S* s) {\n  delete s;\n  s->x = 1;\n}\n")
    (f,) = scan(tmp_path, deps=False).findings
    assert [(s.line, s.label) for s in f.trace] == [(2, "source"), (3, "sink")]
