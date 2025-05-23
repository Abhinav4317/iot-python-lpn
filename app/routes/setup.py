from fastapi import APIRouter
from pathlib import Path
import random, json
import time
router = APIRouter()
SETUP = Path("app/data/setup.json")

@router.post("/setup")
async def setup():
    # LPN params
    n, m, eta = 256, 512, 0.25
    # Public matrix A, server secret mk
    t1=time.perf_counter()
    A  = [[random.getrandbits(1) for _ in range(n)] for _ in range(m)]
    mk = [random.getrandbits(1) for _ in range(n)]
    # Public key
    pk = [sum(A[i][j] & mk[j] for j in range(n)) & 1 for i in range(m)]
    t2=time.perf_counter()
    T=t2-t1
    print(f"Time for setup:{T:.6f} seconds")
    SETUP.parent.mkdir(exist_ok=True, parents=True)
    SETUP.write_text(json.dumps({"n":n,"m":m,"eta":eta,"A":A,"mk":mk,"pk":pk}, indent=2))
    return {"message":"Setup done", "params":{"n":n,"m":m,"eta":eta}}
