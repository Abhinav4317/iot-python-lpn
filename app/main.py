from fastapi import FastAPI
from app.routes import setup, registration, login_auth,revocation


app = FastAPI()



# Register routers
app.include_router(setup.router, prefix="/api")
app.include_router(registration.router, prefix="/api")
app.include_router(login_auth.router, prefix="/api")
app.include_router(revocation.router, prefix="/api")
# Root endpoint

@app.get("/")
async def root():
    return {"message": "Welcome to the LPN-based PQFC Server!"}
