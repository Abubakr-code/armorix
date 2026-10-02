"""Taint that crosses PHP files: `include` shares one variable scope."""

import textwrap

from armorix import crossfile
from armorix.finding import Severity
from armorix.scanner import scan


def write(root, files):
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))


def rules(root):
    return sorted((f.rule_id, f.severity, f.file) for f in scan(root, deps=False).findings)


def test_include_of_a_variable_filled_in_another_file(tmp_path):
    write(tmp_path, {
        "source/low.php": "<?php\n$file = $_GET['page'];\n",
        "index.php": "<?php\nrequire_once 'source/low.php';\ninclude($file);\n",
    })
    found = rules(tmp_path)
    assert ("ARX-LFI", Severity.CRITICAL, "index.php") in found


def test_trace_names_the_file_that_filled_it(tmp_path):
    write(tmp_path, {
        "a.php": "<?php\n$page = $_GET['p'];\n",
        "b.php": "<?php\nrequire 'a.php';\ninclude($page);\n",
    })
    lfi = next(f for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-LFI")
    assert "a.php" in lfi.message


def test_a_file_that_binds_the_name_itself_is_untouched(tmp_path):
    write(tmp_path, {
        "a.php": "<?php\n$tpl = $_GET['t'];\n",
        "b.php": "<?php\n$tpl = 'home.php';\ninclude($tpl);\n",
    })
    assert not [f for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-LFI"]


def test_foreach_counts_as_binding_the_name(tmp_path):
    # WordPress: wp-settings.php includes $theme from its own foreach, unrelated to wp-admin's $theme.
    write(tmp_path, {
        "a.php": "<?php\n$theme = $_GET['theme'];\n",
        "b.php": "<?php\nforeach (active_themes() as $theme) {\n  include $theme . '/functions.php';\n}\n",
    })
    assert not [f for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-LFI"]


def test_a_value_checked_before_it_is_stored_is_not_a_source(tmp_path):
    write(tmp_path, {
        "a.php": "<?php\nif (isset($_GET['tax']) && taxonomy_exists($_GET['tax'])) {\n"
                 "  $taxnow = $_GET['tax'];\n} else {\n  $taxnow = '';\n}\n",
        "b.php": "<?php\necho \"<h1>$taxnow</h1>\";\n",
    })
    assert not [f for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-XSS"]


def test_sources_pass_reports_where_the_value_came_from(tmp_path):
    write(tmp_path, {"x.php": "<?php\n\n$id = $_POST['id'];\n"})
    found = crossfile.php_sources([(tmp_path / "x.php", "x.php")])
    assert {k: v[:2] for k, v in found.items()} == {"id": ("x.php", 3)}


def test_two_unrelated_pages_sharing_a_name_are_not_linked(tmp_path):
    # WordPress: wp-signup.php fills $user_email from $_POST; options-discussion.php uses an unrelated $user_email
    write(tmp_path, {
        "signup.php": "<?php\n$user_email = $_POST['email'];\n",
        "options.php": "<?php\necho \"<p>$user_email</p>\";\n",
    })
    assert not [f for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-XSS"]


def test_a_view_included_by_the_controller_inherits_its_variables(tmp_path):
    write(tmp_path, {
        "controller.php": "<?php\n$name = $_GET['n'];\ninclude 'view.php';\n",
        "view.php": "<?php\necho \"<h1>$name</h1>\";\n",
    })
    assert [f for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-XSS" and f.file == "view.php"]


# ── <script> inside a PHP page ──────────────────────────────────
def test_dom_xss_inside_a_php_page(tmp_path):
    write(tmp_path, {
        "index.php": '<?php\n$page = <<<EOF\n<script>\n'
                     '  var lang = document.location.href.substring(8);\n'
                     '  document.write("<option>" + lang + "</option>");\n'
                     '</script>\nEOF;\n',
    })
    found = [f for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-XSS"]
    assert found and found[0].line == 5  # the line the developer will open


def test_external_and_non_javascript_script_tags_are_left_alone(tmp_path):
    write(tmp_path, {
        "a.php": '<?php ?>\n<script src="/app.js"></script>\n'
                 '<script type="application/json">{"a": 1}</script>\n',
    })
    assert not scan(tmp_path, deps=False).findings


def test_php_inside_a_script_block_is_not_parsed_as_javascript(tmp_path):
    write(tmp_path, {
        "a.php": '<script>\n  var n = <?php echo (int) $_GET["n"]; ?>;\n  console.log(n);\n</script>\n',
    })
    assert not [f for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-XSS"]
