"""FastAPI application initialization for sqlilab microservice."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sqlilab.api.routes import router
from sqlilab.config.settings import get_settings


def create_app() -> FastAPI:
    """Build and configure the FastAPI application instance."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description=(
            "Enterprise-Grade SQL Injection Detection Engine and Defensive Lab Microservice."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


app = create_app()
