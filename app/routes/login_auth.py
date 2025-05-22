# app/api/login_router.py

from fastapi import APIRouter, HTTPException
from pathlib import Path
import json, random, hmac, hashlib, base64
from typing import List
from reedsolo import ReedSolomonError
from app.core.ecc import rsc, BYTES, NSYM 
import time
router = APIRouter()

SETUP_PATH     = Path("app/data/setup_data.json")
REG_PATH       = Path("app/data/registration_data.json")
SMARTCARD_PATH = Path("app/data/smart_card.json")


def bits_to_bytes(bits: List[int]) -> bytes:
    ba=bytearray()
    for i in range(0,len(bits),8):
        ba.append(int("".join(str(b) for b in bits[i:i+8]),2))
    return bytes(ba)

def bytes_to_bits(b: bytes)->List[int]:
    out=[]
    for byte in b:
        out.extend([int(bit) for bit in f"{byte:08b}"])
    return out

def generate_noise(length:int, eta:float)->List[int]:
    return [1 if random.random()<eta else 0 for _ in range(length)]

@router.post("/login-auth")
async def login_auth(payload: dict):
    # load all
    setup = json.loads(SETUP_PATH.read_text())
    reg   = json.loads(REG_PATH.read_text())
    sc    = json.loads(SMARTCARD_PATH.read_text())
    n,m,eta = setup["n"],setup["m"],setup["eta"]
    A, _    = setup["A"], setup["pk"]

    ID_i = payload.get("ID_i"); B_i = payload.get("B_i")
    if ID_i!=reg["ID_i"] or not isinstance(B_i,list) or len(B_i)!=384:
        raise HTTPException(400,"Bad creds")

    t1=time.perf_counter()
    # 1) recover r from HD+biometric
    x_q = B_i+[0]*(512-384)
    hd_bytes = base64.b64decode(sc["HD_b64"])
    # rebuild cw′:
    data_bytes = bits_to_bytes(x_q)
    # first 64 bytes: cw_i = hd_i ^ data_bytes_i
    cw_prime = bytearray(BYTES + NSYM)
    for i in range(BYTES):
        cw_prime[i] = hd_bytes[i] ^ data_bytes[i]
    # parity bytes
    for i in range(BYTES, BYTES+NSYM):
        cw_prime[i] = hd_bytes[i]
    # decode
    try:
        decoded = rsc.decode(bytes(cw_prime))
    except ReedSolomonError:
        raise HTTPException(401,"Fuzzy decode failed")
    r = decoded[0]  # first 16 bytes
    h_r_stored = bytes.fromhex(reg["h_r"])
    if hashlib.sha3_256(r).digest()!=h_r_stored:
        raise HTTPException(401,"r‑hash mismatch")

    # 2) LPN commitment: form beta_q
    v_i = sc["v_i"]
    w   = [sum(A[i][j]&v_i[j] for j in range(n))&1 for i in range(m)]
    e_p = generate_noise(m,eta)
    beta_q = [(w[i]^e_p[i]^x_q[i]) for i in range(m)]

    # 3) client nonce & M1
    N_u = bytes.fromhex(sc["N_hex"])  # reuse stored N
    mac1 = hmac.new(h_r_stored, digestmod=hashlib.sha3_256)
    mac1.update(ID_i.encode()); mac1.update(bits_to_bytes(beta_q)); mac1.update(N_u)
    M1 = mac1.digest()
    if payload.get("M1", M1.hex())!=M1.hex():
        raise HTTPException(401,"M1 bad")

    # 4) server nonce, session key & M2
    N_s = random.randbytes(16)
    K   = hashlib.sha3_256(r+N_u+N_s).digest()
    mac2 = hmac.new(h_r_stored, digestmod=hashlib.sha3_256)
    mac2.update(ID_i.encode()); mac2.update(N_s); mac2.update(K)
    M2 = mac2.digest()

    t2=time.perf_counter()

    T=t2-t1
    print(f"Time for login:{T:.6f} seconds")
    # optional replay guard
    reg["last_N_u"]=payload.get("N_u",N_u.hex())
    REG_PATH.write_text(json.dumps(reg,indent=2))

    return {
        "beta_q":      beta_q,
        "N_u":         N_u.hex(),
        "M1":          M1.hex(),
        "N_s":         N_s.hex(),
        "M2":          M2.hex(),
        "session_key": K.hex()
    }
