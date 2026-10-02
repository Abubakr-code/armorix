"""Taint that crosses JavaScript / TypeScript / Python modules, and into server-side templates."""

import textwrap

from armorix.finding import Severity
from armorix.scanner import scan


def write(root, files):
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")


def found(root):
    return sorted((f.rule_id, f.severity, f.file) for f in scan(root, deps=False).findings)


def test_route_to_dao_through_require_and_new(tmp_path):
    # NodeGoat's shape: the route reads the query, the DAO in another file builds $where from it
    write(tmp_path, {
        "routes/a.js": """
            const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
            const dao = new AllocationsDAO(db);
            app.get('/a', (req, res) => { dao.getByThreshold(req.query.threshold, cb) });
        """,
        "data/allocations-dao.js": """
            function AllocationsDAO(db) {
              this.getByThreshold = (threshold, cb) => {
                db.allocations.find({ $where: `this.stocks > '${threshold}'` });
              };
            }
            module.exports.AllocationsDAO = AllocationsDAO;
        """,
    })
    assert ("ARX-NOSQL", Severity.CRITICAL, "data/allocations-dao.js") in found(tmp_path)


def test_three_layers_through_es_imports(tmp_path):
    write(tmp_path, {
        "src/routes.ts": """
            import { lookup } from './service'
            app.get('/u', (req, res) => lookup(req.query.name))
        """,
        "src/service.ts": """
            import * as repo from './repo'
            export function lookup(name) { return repo.byName(name) }
        """,
        "src/repo.ts": """
            export function byName(name) { return db.query("SELECT * FROM users WHERE name = '" + name + "'") }
        """,
    })
    assert ("ARX-SQLI", Severity.CRITICAL, "src/repo.ts") in found(tmp_path)


def test_python_view_to_helper_module(tmp_path):
    write(tmp_path, {
        "app/views.py": """
            from flask import request
            from .helpers import run_ping
            def ping():
                return run_ping(request.args["host"])
        """,
        "app/helpers.py": """
            import os
            def run_ping(host):
                return os.system("ping -c1 " + host)
        """,
        "app/__init__.py": "",
    })
    assert ("ARX-CMDI", Severity.CRITICAL, "app/helpers.py") in found(tmp_path)


def test_a_method_is_not_matched_by_name_alone(tmp_path):
    # WordPress: api.Class.extend(...) must not land on some unrelated file's extend()
    write(tmp_path, {
        "a.js": "const q = location.search.substr(1);\napi.Class.mergeDeep(q);\n",
        "lib/other.js": "function mergeDeep(src) { for (const k in src) target[k][src[k]] = 1 }\n",
    })
    assert not [f for f in scan(tmp_path, deps=False).findings if f.file == "lib/other.js"]


def test_template_raw_output_is_a_lead_until_a_controller_feeds_it(tmp_path):
    write(tmp_path, {"views/page.ejs": "<p><%- note %></p>\n<p><%= safe %></p>\n"})
    assert found(tmp_path) == [("ARX-XSS", Severity.MEDIUM, "views/page.ejs")]


def test_template_raw_output_fed_by_the_request_is_high(tmp_path):
    write(tmp_path, {
        "views/app/products.ejs": "Results for <%- output.searchTerm %>\n<%- include('footer') %>\n",
        "core/handler.js": "app.post('/s', (req, res) => res.render('app/products', { output: { searchTerm: req.body.q } }))\n",
    })
    xss = [f for f in scan(tmp_path, deps=False).findings if f.file.endswith(".ejs")]
    assert len(xss) == 1 and xss[0].severity == Severity.HIGH and "req.body.q" in xss[0].message


def test_jinja_safe_filter_fed_by_flask(tmp_path):
    write(tmp_path, {
        "templates/hello.html": "<h1>{{ name|safe }}</h1>\n<p>{{ other }}</p>\n",
        "app.py": "from flask import request, render_template\ndef h():\n    return render_template('hello.html', name=request.args['n'])\n",
    })
    xss = [f for f in scan(tmp_path, deps=False).findings if f.file.endswith(".html")]
    assert [(f.line, f.severity) for f in xss] == [(1, Severity.HIGH)]
