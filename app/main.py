from fastapi import FastAPI
from app.routes import setup, registration, login_auth,revocation
from app.core.ecc import rsc, BYTES, NSYM

app = FastAPI()

# Pre‑warm the RSCodec tables at startup
@app.on_event("startup")
async def warm_ecc():
    # Prepare a dummy all‑zero data block of exactly BYTES length
    dummy_data = bytes([0] * BYTES)
    # This first encode will build internal GF tables
    codeword = rsc.encode(dummy_data)
    # And this decode will warm any decode‐side tables
    _ = rsc.decode(codeword)

# Register routers
app.include_router(setup.router, prefix="/api")
app.include_router(registration.router, prefix="/api")
app.include_router(login_auth.router, prefix="/api")
app.include_router(revocation.router, prefix="/api")
# Root endpoint

@app.get("/")
async def root():
    return {"message": "Welcome to the LPN-based PQFC Server!"}
