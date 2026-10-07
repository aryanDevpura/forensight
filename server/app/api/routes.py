from fastapi import APIRouter
from server.app.api.endpoints.health import router as health_router
from server.app.api.endpoints.system import router as system_router
from server.app.api.endpoints.evidence import router as evidence_router
from server.app.api.endpoints.custody import router as custody_router
from server.app.api.endpoints.analysis import router as analysis_router
from server.app.api.endpoints.timeline import router as timeline_router

api_router = APIRouter(prefix="/api")

api_router.include_router(health_router)
api_router.include_router(system_router)
api_router.include_router(evidence_router)
api_router.include_router(custody_router)
api_router.include_router(analysis_router)
api_router.include_router(timeline_router)

