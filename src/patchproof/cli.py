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
         export_check: Path | None = typer.Option(None), allow_local: bool = False):
    """Make one GET and optionally export a finding's CheckSpec."""
    try:
        result = service.scan(url, allow_local=allow_local)
        if export_check is not None:
            if result.finding is None:
                error('No finding to export; no CheckSpec was written.', format)
            service.export_check(result.finding, export_check)
    except (ValueError, OSError):
        error('Invalid target or unable to write CheckSpec.', format)
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


if __name__ == '__main__':
    app()
