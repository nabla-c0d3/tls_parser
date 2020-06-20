from invoke import task, Context


@task
def test(ctx):
    # type: (Context) -> None
    # Run the test suite
    ctx.run("pytest --cov=tls_parser")

    # Run linters
    ctx.run("flake8 .")
    ctx.run("mypy .")
    ctx.run("black -l 120 tls_parser tests tasks.py --check")
