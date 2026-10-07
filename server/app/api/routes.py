from fastapi import APIRouter
from server.app.api.endpoints.health import router as health_router
from server.app.api.endpoints.system import router as system_router
from server.app.api.endpoints.evidence import router as evidence_router

api_router = APIRouter(prefix="/api")

api_router.include_router(health_router)
api_router.include_router(system_router)
api_router.include_router(evidence_router)
