# app/api/registration_router.py

from fastapi import APIRouter, HTTPException
from pathlib import Path
import random, json, hashlib, hmac, base64
from typing import List
import time
from app.core.ecc import rsc, BYTES, NSYM 
router = APIRouter()

SETUP_PATH      = Path("app/data/setup_data.json")
REG_PATH        = Path("app/data/registration_data.json")
SMARTCARD_PATH  = Path("app/data/smart_card.json")


def bits_to_bytes(bits: List[int]) -> bytes:
    ba = bytearray()
    for i in range(0, len(bits), 8):
        ba.append(int("".join(str(b) for b in bits[i:i+8]), 2))
    return bytes(ba)

def generate_noise(length:int, eta:float)->List[int]:
    return [1 if random.random()<eta else 0 for _ in range(length)]

@router.post("/register")
async def register(user_data: dict):
    # load params
    if not SETUP_PATH.exists(): raise HTTPException(500,"No setup")
    setup = json.loads(SETUP_PATH.read_text())
    n,m,eta = setup["n"],setup["m"],setup["eta"]
    A, mk  = setup["A"], setup["mk"]

    ID_i = user_data.get("ID_i")
    B_i  = user_data.get("B_i")
    if not ID_i or not isinstance(B_i,list) or len(B_i)!=384:
        raise HTTPException(400,"Need ID_i + 384‑bit B_i")
    t1=time.perf_counter()
    # pad biometric
    x_r = B_i + [0]*(512-384)

    # 1) pick r (16 bytes) + store its hash
    r = random.randbytes(BYTES)           # <- 64 bytes, not 16
    h_r = hashlib.sha3_256(r).digest()

    # 2) ECC‑encode r → cw (64+NSYM bytes)
    cw     = rsc.encode(r)

    # 3) build helper_data = cw ⊕ ( data_bytes ∥ 0^NSYM )
    data_bytes = bits_to_bytes(x_r)  # using only biometric here
    pad        = b"\x00"*NSYM
    padded     = data_bytes + pad    # length=64+NSYM
    hd_bytes   = bytes(cw_byte ^ padded[i] for i,cw_byte in enumerate(cw))

    # 4) LPN mask: pick v_i,e → beta
    v_i = [random.getrandbits(1) for _ in range(n)]
    e   = generate_noise(m,eta)
    w   = [sum(A[i][j]&v_i[j] for j in range(n))&1 for i in range(m)]
    beta= [(w[i]^e[i]^(x_r[i])) for i in range(m)]

    # 5) HMAC under h_r
    mac = hmac.new(h_r,digestmod=hashlib.sha3_256)
    mac.update(ID_i.encode()); mac.update(bits_to_bytes(beta))
    sigma = mac.digest()
    t2=time.perf_counter()

    T=t2-t1
    print(f"Time for registration:{T:.6f} seconds")
    # 6) persist server record
    REG_PATH.write_text(json.dumps({
        "ID_i":   ID_i,
        "beta":   beta,
        "h_r":    h_r.hex(),
        "sigma":  sigma.hex()
    }, indent=2))

    # 7) persist smart‑card blob
    SMARTCARD_PATH.write_text(json.dumps({
        "v_i":     v_i,
        "N_hex":   random.randbytes(16).hex(),
        "HD_b64":  base64.b64encode(hd_bytes).decode()
    }, indent=2))

    return {"message":"Registration OK"}
