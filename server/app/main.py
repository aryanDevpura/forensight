from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from server.app.core.config import settings
from server.app.database.session import init_db
from server.app.api.routes import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and storage directories on startup
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="ForenSight - Digital Evidence Collection and Forensic Analysis Investigation Server",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration for local frontend and collector development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(api_router)


@app.get("/", tags=["Root"])
def root():
    return {
        "system": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "health_check": "/api/health",
        "api_docs": "/docs",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "server.app.main:app",
        host=settings.FORENSIGHT_SERVER_HOST,
        port=settings.FORENSIGHT_SERVER_PORT,
        reload=settings.FORENSIGHT_DEBUG,
    )
