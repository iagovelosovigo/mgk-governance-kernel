import ast
from pathlib import Path


def _without_docstring(statements):
    if (
        statements
        and isinstance(statements[0], ast.Expr)
        and isinstance(statements[0].value, ast.Constant)
        and isinstance(statements[0].value.value, str)
    ):
        return statements[1:]
    return statements


def test_hello_world():
    generated = Path("src/generated")
    hello_path = generated / "hello.py"
    keep_path = generated / ".keep"
    assert not generated.is_symlink() and generated.is_dir(), "generated directory missing or symlinked"
    assert not hello_path.is_symlink() and hello_path.is_file(), "hello.py must be a regular file"
    assert not keep_path.is_symlink() and keep_path.is_file(), ".keep must remain a regular file"
    assert keep_path.read_bytes() == b"", ".keep must remain empty"
    assert sorted(path.name for path in generated.iterdir()) == [".keep", "hello.py"], (
        "F00 may only add hello.py"
    )
    source = hello_path.read_text(encoding="utf-8")
    assert len(source.encode("utf-8")) <= 4096, "hello.py exceeds size limit"
    module = ast.parse(source, filename=str(hello_path), mode="exec")
    module_body = _without_docstring(module.body)
    assert len(module_body) == 1 and isinstance(module_body[0], (ast.FunctionDef, ast.AsyncFunctionDef)), (
        "hello.py must contain only hello()"
    )
    function = module_body[0]
    assert isinstance(function, ast.FunctionDef), "hello() must be synchronous"
    assert function.name == "hello" and not function.decorator_list, "invalid hello() declaration"
    assert not getattr(function, "type_params", []), "generic hello() is forbidden"
    assert function.returns is None or (
        isinstance(function.returns, ast.Name) and function.returns.id == "str"
    ), "hello() return annotation must be absent or str"
    args = function.args
    assert not any(
        [args.posonlyargs, args.args, args.kwonlyargs, args.defaults, args.kw_defaults]
    ) and args.vararg is None and args.kwarg is None, "hello() must take no arguments"
    body = _without_docstring(function.body)
    assert len(body) == 1 and isinstance(body[0], ast.Return), "hello() must contain one return"
    value = body[0].value
    assert isinstance(value, ast.Constant) and value.value == "Hello, MGK!", (
        "hello() must return the exact expected string"
    )
