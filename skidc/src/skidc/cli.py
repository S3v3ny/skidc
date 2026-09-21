from pathlib import Path

import click
import uvicorn

from skidc.dispatcher.logging import configure_logging
from skidc.server import db


@click.group()
def main():
    """Skidc - blackboard fact-graph state-space search over pluggable coding-agent backends."""


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option("--port", default=8000, show_default=True, help="Bind port")
@click.option(
    "--db-path",
    type=click.Path(),
    default=str(db.DEFAULT_DB),
    show_default=True,
    help="SQLite database path",
)
@click.option("--log-level", default="info", show_default=True, help="Uvicorn log level")
@click.option("--access-log/--no-access-log", default=True, show_default=True, help="Enable Uvicorn access log")
def serve(host: str, port: int, db_path: str, log_level: str, access_log: bool):
    """Start the Skidc API server."""
    db.configure(Path(db_path))
    from skidc.server.app import app

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level.lower(),
        access_log=access_log,
    )


@main.command()
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Dispatcher config path",
)
@click.option("--once", is_flag=True, help="Run one scheduling iteration and exit")
@click.option(
    "--startup-healthcheck-only",
    is_flag=True,
    help="Run startup worker healthchecks and exit",
)
@click.option("--log-level", default="INFO", show_default=True, help="Log level")
def dispatch(config_path: Path, once: bool, startup_healthcheck_only: bool, log_level: str):
    """Run the Skidc dispatcher."""
    configure_logging(log_level, bare=startup_healthcheck_only)
    from skidc.dispatcher.scheduler.loop import DispatcherLoop

    loop = DispatcherLoop(config_path)
    try:
        if startup_healthcheck_only:
            loop.run_startup_healthchecks_only()
            return
        loop.run(once=once)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


@main.command("android-mcp")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option("--port", default=8765, show_default=True, help="Bind port")
@click.option("--adb-path", default="adb", show_default=True, help="Path to adb executable")
@click.option("--device-id", default=None, help="ADB device id, e.g. emulator-5554")
@click.option("--timeout", default=20, show_default=True, help="ADB command timeout in seconds")
@click.option("--log-level", default="info", show_default=True, help="Uvicorn log level")
def android_mcp(host: str, port: int, adb_path: str, device_id: str | None, timeout: int, log_level: str):
    """Start the Android MCP Bridge — HTTP control surface for emulator/app targets.

    Launches a FastAPI server that wraps ADB commands (install, tap, screenshot,
    UI tree dump, etc.) into REST endpoints. Workers call these endpoints to
    operate Android apps during exploration tasks.

    Requires: adb on PATH (or --adb-path) and a connected device/emulator.
    """
    from skidc.android_mcp.app import app, configure

    configure(adb_path=adb_path, device_id=device_id, timeout=timeout)
    uvicorn.run(app, host=host, port=port, log_level=log_level.lower())
