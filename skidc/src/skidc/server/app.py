from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from skidc import __version__
from skidc.server import db
from skidc.server.routers import attack_paths, coverage, export, hints, hypotheses, intents, projects, settings, logs
from skidc.server.services import reconcile_project_coverage

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.configure(db.DEFAULT_DB)
    with db.get_conn() as conn:
        project_rows = conn.execute("SELECT id FROM projects").fetchall()
        for project_row in project_rows:
            reconcile_project_coverage(conn, project_row["id"])
    yield


app = FastAPI(
    title="Skidc",
    description="Blackboard fact-graph state-space search over pluggable coding-agent backends",
    version=__version__,
    lifespan=lifespan,
)

app.include_router(settings.router)
app.include_router(projects.router)
app.include_router(hints.router)
app.include_router(intents.router)
app.include_router(attack_paths.router)
app.include_router(hypotheses.router)
app.include_router(coverage.router)
app.include_router(export.router)
app.include_router(logs.router)

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
