from fastapi import APIRouter, HTTPException
from pathlib import Path
import random, json, hashlib, hmac
from typing import List
import time
router = APIRouter()
SETUP      = Path("app/data/setup.json")
REG_DB     = Path("app/data/reg_db.json")
SMARTCARD  = Path("app/data/card.json")

def bits_to_bytes(bits: List[int]) -> bytes:
    ba = bytearray()
    for i in range(0,len(bits),8):
        ba.append(int("".join(str(b) for b in bits[i:i+8]),2))
    return bytes(ba)

@router.post("/register")
async def register(data: dict):
    # load params
    if not SETUP.exists():
        raise HTTPException(500, "Not initialized")
    setup = json.loads(SETUP.read_text())
    n,m,eta = setup["n"], setup["m"], setup["eta"]
    A, mk, pk = setup["A"], setup["mk"], setup["pk"]

    # user input
    ID_i = data.get("ID_i")
    B_i  = data.get("B_i")
    if not ID_i or not isinstance(B_i,list) or len(B_i)!=384:
        raise HTTPException(400,"Need ID_i + 384-bit B_i")

    # pad biometric
    t1=time.perf_counter()
    x_r = B_i + [0]*(512-384)

    # generate key & nonce
    k_i = [random.getrandbits(1) for _ in range(128)]
    N   = [random.getrandbits(1) for _ in range(128)]
    c_i = hashlib.sha3_256(bits_to_bytes(k_i+N)).digest()

    # sample v,e
    v_i = [random.getrandbits(1) for _ in range(n)]
    e   = [1 if random.random()<eta else 0 for _ in range(m)]

    # compute w and β
    w_i    = [sum(A[i][j]&v_i[j] for j in range(n))&1 for i in range(m)]
    b_bits = x_r + k_i
    beta_r = [(w_i[i]^e[i]^b_bits[i]) for i in range(m)]

    # r_i, Z_i, δ_i, e_i
    r_i    = hashlib.sha3_256(c_i + bits_to_bytes(beta_r)).digest()
    Z_i    = [(w_i[i]^pk[i]) for i in range(m)]
    h_wi   = hashlib.sha3_256(bits_to_bytes(w_i)).digest()
    h_IDr  = hashlib.sha3_256(ID_i.encode()+r_i).digest()
    delta  = bytes(a^b for a,b in zip(h_wi,h_IDr))
    h_IDmk = hashlib.sha3_256(ID_i.encode()+bits_to_bytes(mk)).digest()
    e_i = hmac.new(
        key=bits_to_bytes(mk),
        msg=ID_i.encode() + r_i,
        digestmod=hashlib.sha3_256
    ).digest()
    t2=time.perf_counter()
    T=t2-t1
    print(f"Time for registration:{T:.6f} seconds")
    # store server record and card blob
    REG_DB.write_text(json.dumps({
        "ID_i": ID_i, "beta_r": beta_r,"c_i":   c_i.hex(), "r_i": r_i.hex(),
        "Z_i": Z_i, "delta": delta.hex()
    }, indent=2))
    SMARTCARD.write_text(json.dumps({
        "v_i": v_i, "e": e, "w_i": w_i,
        "beta_r": beta_r, "k_i": k_i, "N": N,"e_i":e_i.hex()
    }, indent=2))

    return {"message":"Registered"}
