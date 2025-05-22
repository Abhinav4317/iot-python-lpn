# app/api/setup_router.py

from fastapi import APIRouter
import random, json
from pathlib import Path
import time
router = APIRouter()

SETUP_PATH = Path("app/data/setup_data.json")

@router.post("/setup")
async def setup_phase():
    n, m, eta = 256, 512, 0.05  # LPN params
    # 1) Build A, mk
    t1=time.perf_counter()
    A  = [[random.getrandbits(1) for _ in range(n)] for _ in range(m)]
    mk = [random.getrandbits(1) for _ in range(n)]
    # 2) Build PK = A·mk mod2
    pk = [sum(A[i][j] & mk[j] for j in range(n)) & 1 for i in range(m)]
    t2=time.perf_counter()
    T=t2-t1
    print(f"Time for setup:{T:.6f} seconds")
    SETUP_PATH.parent.mkdir(exist_ok=True, parents=True)
    with open(SETUP_PATH, "w") as f:
        json.dump({"n":n,"m":m,"eta":eta,"A":A,"pk":pk,"mk":mk}, f, indent=2)

    return {"message":"Setup done", "public": {"n":n,"m":m,"eta":eta,"A":A,"pk":pk}}
