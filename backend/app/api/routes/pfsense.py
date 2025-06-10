import logging
from pathlib import Path
import uuid
from typing import Any

from app.rag.generate_config import wygeneruj_zmiane_konfiguracji
from app.pfsense.config import PfSenseConfig
from fastapi import APIRouter, HTTPException

from app.api.deps import SessionDep
from app.models import Message, Prompt
from app.pfsense.utils import (
    fetch_pfsense_config,
    push_pfsense_config,
    validate_pfsense_config,
    load_pfsense_config_from_file,
)

router = APIRouter(prefix="/pfsense", tags=["pfsense"])


@router.get("/")
def read_config(session: SessionDep) -> PfSenseConfig:
    """
    Retrieve configuration from Pfsense.
    """
    return fetch_pfsense_config()


@router.post("/", response_model=PfSenseConfig)
async def push_config(
    *,
    session: SessionDep,
    prompt: Prompt,
    commit: bool = True,
) -> Any:
    """Push configuration to Pfsense based on the provided prompt."""
    logging.info("Received prompt: %s", prompt.text)
    # config = fetch_pfsense_config()
    config = load_pfsense_config_from_file(
        str(Path("data/example_config.xml").absolute())
    )
    if not config:
        logging.error("Configuration not found")
        raise HTTPException(status_code=404, detail="Configuration not found")

    updated_config = wygeneruj_zmiane_konfiguracji(prompt.text, config)
    if not updated_config:
        logging.error("Failed to generate configuration change")
        raise HTTPException(
            status_code=400,
            detail="Failed to generate configuration change",
        )
    config.update_from_output(updated_config)

    if commit:
        push_pfsense_config(config=config)

    return config


@router.post("/config", response_model=PfSenseConfig)
def update_config(
    *,
    session: SessionDep,
    config: PfSenseConfig,
    dry_run: bool = False,
) -> PfSenseConfig:
    """
    Update an config based on the provided prompt.
    """
    if not config:
        raise HTTPException(status_code=400, detail="Configuration is required")

    if not validate_pfsense_config(config):
        raise HTTPException(status_code=400, detail="Invalid pfSense configuration")

    if not push_pfsense_config(config=config):
        raise HTTPException(
            status_code=500,
            detail="Failed to push pfSense configuration",
        )

    return config


@router.delete("/", response_model=Message)
def delete_config(
    session: SessionDep,
    id: uuid.UUID,
) -> Message:
    """
    Reset Pfsense to factory defaults.
    This endpoint is currently disabled for safety reasons.
    """
    return Message(message="Configuration deleted successfully")
