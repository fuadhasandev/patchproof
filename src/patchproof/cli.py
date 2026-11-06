import json
from enum import Enum
from pathlib import Path
import typer
from . import service
from .reporting import render

app = typer.Typer(help='PatchProof: scan only websites you own or have permission to test.', pretty_exceptions_enable=False)


class Format(str, Enum):
    text = 'text'
    json = 'json'


def error(message, format):
    typer.echo(json.dumps({'error': message}) if format == Format.json else 'Error: ' + message)
    raise typer.Exit(2)


@app.command()
def scan(url: str, format: Format = typer.Option(Format.text),
         export_check: Path | None = typer.Option(None),
         export_checks: Path | None = typer.Option(None),
         session_cookie: list[str] | None = typer.Option(None), allow_local: bool = False):
    """Make one GET for all checks and optionally export finding specs."""
    if export_check is not None and export_checks is not None:
        error('Choose --export-check or --export-checks, not both.', format)
    try:
        result = service.scan(url, allow_local=allow_local, session_cookies=session_cookie or ())
        if export_check is not None or export_checks is not None:
            if not result.findings:
                error('No findings to export; no CheckSpec was written.', format)
            if export_check is not None:
                if len(result.findings) != 1:
                    error('Multiple findings: use --export-checks DIR.', format)
                service.export_check(result.findings[0], export_check)
            else:
                service.export_checks(result.findings, export_checks)
    except FileExistsError:
        error('Export destination already exists; choose a new file or directory.', format)
    except (ValueError, OSError):
        error('Invalid target/cookie name or unable to write CheckSpec.', format)
    typer.echo(render(result, format.value))
    raise typer.Exit(2 if result.status == 'unverified' else 0)


@app.command()
def replay(path: Path, format: Format = typer.Option(Format.text), allow_local: bool = False):
    """Replay a check: exits 0 resolved, 1 still present, 2 unverified/invalid."""
    try:
        result = service.replay(path, allow_local=allow_local)
    except service.SpecError as exc:
        error(str(exc), format)
    typer.echo(render(result, format.value))
    raise typer.Exit({'resolved': 0, 'still_present': 1, 'unverified': 2}[result.status])


@app.command()
def investigate(url: str, format: Format = typer.Option(Format.text),
                session_cookie: list[str] | None = typer.Option(None), allow_local: bool = False):
    """Scan first, then optionally investigate through bounded OpenRouter tools."""
    from .investigation import investigate as run, render_investigation, exit_code
    try:
        result = run(url, allow_local=allow_local, session_cookies=session_cookie or ())
    except ValueError:
        error('Invalid target or cookie name; OpenRouter was not called.', format)
    typer.echo(render_investigation(result, format.value))
    raise typer.Exit(exit_code(result))


if __name__ == '__main__':
    app()
