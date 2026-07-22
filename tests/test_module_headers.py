"""Architecture test enforcing descriptive headers for Python modules.

Scans production, evaluation, and test translation units and requires a
non-trivial module docstring that can serve documentation and introspection.
"""

import ast
from pathlib import Path


def test_every_python_module_has_a_descriptive_header():
    repository = Path(__file__).resolve().parents[1]
    modules = sorted(
        path
        for directory in (repository / "src", repository / "eval", repository / "tests")
        for path in directory.rglob("*.py")
    )

    missing = []
    for path in modules:
        module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        description = ast.get_docstring(module, clean=True)
        if description is None or len(description.split()) < 8:
            missing.append(str(path.relative_to(repository)))

    assert not missing, f"Modules without descriptive headers: {missing}"
