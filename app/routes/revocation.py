# app/api/revocation_router.py

from fastapi import APIRouter, HTTPException
from pathlib import Path
import json
from app.routes.registration import register  # reuse logic
from app.routes.login_auth import login_auth
import time
# Alternatively, copy the same steps as registration after verifying biometric
router = APIRouter()

@router.post("/revoke")
async def revoke(payload: dict):
    # first do login‐auth to verify biometric & recover r
    # If login_auth() returns OK, proceed to a fresh register() for ID_i + B_i
    await login_auth({"ID_i":payload["ID_i"], "B_i":payload["B_i"]})
    # now re‐register
    return await register(payload)
