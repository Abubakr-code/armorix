"""Which names a file defines vs. uses — lets the fixer reject patches that call made-up helpers."""

from __future__ import annotations

import builtins

from .parsing import SourceFile, text

JS_GLOBALS = {
    "undefined", "NaN", "Infinity", "globalThis", "window", "document", "navigator", "location", "console", "process", "Buffer",
    "require", "module", "exports", "__dirname", "__filename", "JSON", "Math", "Object", "Array", "String", "Number", "Boolean",
    "Symbol", "BigInt", "Date", "RegExp", "Error", "TypeError", "RangeError", "SyntaxError", "Promise", "Map", "Set", "WeakMap",
    "WeakSet", "Reflect", "Proxy", "Intl", "URL", "URLSearchParams", "TextEncoder", "TextDecoder", "AbortController", "fetch",
    "Headers", "Request", "Response", "FormData", "Blob", "crypto", "structuredClone", "setTimeout", "clearTimeout",
    "setInterval", "clearInterval", "setImmediate", "queueMicrotask", "parseInt", "parseFloat", "isNaN", "isFinite",
    "encodeURIComponent", "decodeURIComponent", "encodeURI", "decodeURI", "escape", "arguments", "this", "super",
}
PY_GLOBALS = set(dir(builtins)) | {"__name__", "__file__", "self", "cls"}

JS_DECL_PARENTS = {
    "variable_declarator": "name", "function_declaration": "name", "class_declaration": "name", "formal_parameters": None,
    "import_specifier": None, "import_clause": None, "namespace_import": None, "catch_clause": "parameter",
    "arrow_function": "parameter", "required_parameter": "pattern", "optional_parameter": "pattern",
    "generator_function_declaration": "name", "method_definition": "name", "for_in_statement": "left",
}


def _js(src: SourceFile):
    defined, used = set(), {}
    for n in src.nodes:
        if n.type not in {"identifier", "shorthand_property_identifier_pattern", "shorthand_property_identifier"}:
            continue
        name = text(n)
        declared = False
        cur, parent = n, n.parent
        while parent is not None and parent.type in {"object_pattern", "array_pattern", "pair_pattern", "assignment_pattern", "rest_pattern"}:
            cur, parent = parent, parent.parent
        if parent is not None and parent.type in JS_DECL_PARENTS:
            field = JS_DECL_PARENTS[parent.type]
            declared = field is None or parent.child_by_field_name(field) == cur
        if n.type == "shorthand_property_identifier_pattern":
            declared = True
        if declared:
            defined.add(name)
        else:
            used.setdefault(name, n.start_point[0] + 1)
    return defined, used


PY_DECL_PARENTS = {"function_definition": "name", "class_definition": "name", "parameters": None, "default_parameter": "name",
                   "typed_parameter": None, "typed_default_parameter": "name", "lambda_parameters": None,
                   "aliased_import": "alias", "for_in_clause": "left", "for_statement": "left", "as_pattern_target": None,
                   "global_statement": None, "nonlocal_statement": None}


def _py(src: SourceFile):
    defined, used = set(), {}
    for n in src.nodes:
        if n.type != "identifier":
            continue
        name, parent = text(n), n.parent
        if parent is None:
            continue
        if parent.type == "attribute" and parent.child_by_field_name("attribute") == n:
            continue  # obj.attr — attr is not a variable
        if parent.type == "keyword_argument" and parent.child_by_field_name("name") == n:
            continue
        top = n
        while top.parent is not None and top.parent.type in {"pattern_list", "tuple_pattern", "list_pattern", "expression_list", "list_splat_pattern"}:
            top = top.parent
        p = top.parent
        declared = False
        if p is not None and p.type in {"assignment", "augmented_assignment"} and p.child_by_field_name("left") == top:
            declared = True
        elif p is not None and p.type in PY_DECL_PARENTS:
            field = PY_DECL_PARENTS[p.type]
            declared = field is None or p.child_by_field_name(field) == top
        elif parent.type == "dotted_name" and parent.parent is not None and parent.parent.type in {"import_statement", "import_from_statement"}:
            is_module = parent.parent.type == "import_from_statement" and parent.parent.child_by_field_name("module_name") == parent
            declared = not is_module and parent.named_children[0] == n
        if declared:
            defined.add(name)
        else:
            used.setdefault(name, n.start_point[0] + 1)
    return defined, used


PHP_GLOBALS = {"$this", "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER", "$_SESSION", "$_ENV", "$GLOBALS", "$argv",
               "$argc", "$http_response_header"}
PHP_ASSIGN = {"assignment_expression", "augmented_assignment_expression", "reference_assignment_expression"}
PHP_DECL_PARENTS = {"simple_parameter", "variadic_parameter", "property_promotion_parameter", "global_declaration", "static_variable_declaration",
                    "catch_clause", "anonymous_function_use_clause", "static_variable_declaration"}


def _php(src: SourceFile):
    """PHP variables only: functions and methods come from extensions / frameworks and cannot be checked from one file."""
    defined, used = set(), {}
    for n in src.nodes:
        if n.type != "variable_name":
            continue
        name = text(n)
        declared = n.parent is not None and n.parent.type in PHP_DECL_PARENTS
        cur = n
        while not declared and cur.parent is not None and cur.parent.type not in {"expression_statement", "compound_statement", "program"}:
            parent = cur.parent
            if parent.type in PHP_ASSIGN and parent.child_by_field_name("left") is not None and \
                    parent.child_by_field_name("left").start_byte <= n.start_byte < parent.child_by_field_name("left").end_byte:
                declared = True
            elif parent.type == "foreach_statement" and cur.id != parent.named_children[0].id:
                declared = True
            cur = parent
        if declared:
            defined.add(name)
        else:
            used.setdefault(name, n.start_point[0] + 1)
    return defined, used


def scope(src: SourceFile) -> tuple[set[str], dict[str, int]]:
    """(names defined anywhere in the file, first line each other name is used on).

    C/C++, PHP, Go and Java names mostly come from headers, packages and class libraries that are not in the
    file, so the invented-name guard is skipped there; parse + re-scan still verify the patch.
    """
    if src.family == "php":
        return _php(src)
    if src.family in {"c", "go", "java"}:
        return set(), {}
    return _js(src) if src.family == "js" else _py(src)


def globals_for(family: str) -> set[str]:
    return {"js": JS_GLOBALS, "php": PHP_GLOBALS}.get(family, PY_GLOBALS)
