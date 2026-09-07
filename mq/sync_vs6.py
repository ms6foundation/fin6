"""Generate mq/vs6/{ssh3,mpcith}.py from the ms6 originals.

The repo's zero-prover-dependency rule: nothing in vs6 may import ms6, and a
party that only verifies must be able to audit vs6 alone without loading any
code that produces proofs.  The verifier halves are copied verbatim; the prover
halves are dropped, along with any import they alone needed.
"""
import ast, pathlib, re

DROP_DEFS = {
    "ssh3":   {"prove_hidden3"},
    "mpcith": {"prove_mpcith", "sacrifice_check_in_the_clear"},
}
DROP_ASSIGN = {"ssh3": {"DEFAULT_ROUNDS_3PASS"}, "mpcith": set()}
HEADER = {
    "ssh3": '"""SSH 3-pass MQ verification - verifier half, copied verbatim from the\nprover-side module.\n\nNothing here imports the prover package.  chain/tests/test_mq_backends.py\nasserts the retained functions are character-identical to their originals, which\nis the bit-for-bit regression the package docstrings ask for.\n"""\n',
    "mpcith": '"""MPC-in-the-head verification - verifier half, copied verbatim from the\nprover-side module.\n\nNothing here imports the prover package, and nothing here can produce a proof:\nthe prover and the in-the-clear sacrifice check are dropped, so this module never\ntouches `secrets`.  chain/tests/test_mq_backends.py asserts the retained\nfunctions are character-identical to their originals.\n"""\n',
}

for name in ("ssh3", "mpcith"):
    src = pathlib.Path(f"mq/ms6/{name}.py").read_text()
    tree = ast.parse(src)
    lines = src.splitlines(keepends=True)

    body, import_node = [], None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            if node.name in DROP_DEFS[name]:
                continue
            start = (min(d.lineno for d in node.decorator_list) - 1
                     if node.decorator_list else node.lineno - 1)
            body.append("".join(lines[start:node.end_lineno]))
        elif isinstance(node, ast.ImportFrom) and node.module == "core":
            import_node = node
        elif isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue                                   # re-emitted in the header
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in DROP_ASSIGN[name]
                for t in node.targets):
            continue
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue                                   # module docstring
        elif isinstance(node, ast.Import):
            mods = [a.name for a in node.names if a.name != "secrets"]
            if mods:
                body.append("".join(lines[node.lineno - 1:node.end_lineno]))
        else:
            body.append("".join(lines[node.lineno - 1:node.end_lineno]))

    # keep only the core imports the retained code actually references
    retained = "\n".join(body)
    used = {n.id for n in ast.walk(ast.parse(retained)) if isinstance(n, ast.Name)}
    keep = sorted(a.name for a in import_node.names
                  if a.name in used and a.name != "_secrets")
    imp = "from .core import (" + ", ".join(keep) + ")\n"

    out = HEADER[name] + "from __future__ import annotations\n\n" + imp + "\n\n" + \
        "\n".join(c if c.endswith("\n") else c + "\n" for c in body)
    out = re.sub(r"\n{4,}", "\n\n\n", out)
    pathlib.Path(f"mq/vs6/{name}.py").write_text(out)
    print(f"mq/vs6/{name}.py  <- {len(out.splitlines())} lines, "
          f"imports {len(keep)}, dropped {sorted(DROP_DEFS[name])}")
