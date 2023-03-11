from invoke import task, Context


@task
def test(ctx: Context) -> None:
    # Run linters
    ctx.run("flake8 tls_parser tests")
    ctx.run("mypy tls_parser tests")
    ctx.run("black -l 120 tls_parser tests tasks.py --check")

    # Run the test suite
    ctx.run("pytest --cov=tls_parser --cov-fail-under 80")
