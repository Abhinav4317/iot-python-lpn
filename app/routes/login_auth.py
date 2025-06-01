# app/api/login_router.py

from fastapi import APIRouter, HTTPException
from pathlib import Path
import json, random, hashlib, hmac
from typing import List
import time
SEEN_NONCES = {} 
router = APIRouter()
SETUP_PATH     = Path("app/data/setup.json")
REG_PATH       = Path("app/data/reg_db.json")
SMARTCARD_PATH = Path("app/data/card.json")

def bits_to_bytes(bits: List[int]) -> bytes:
    ba = bytearray()
    for i in range(0, len(bits), 8):
        ba.append(int("".join(str(b) for b in bits[i:i+8]), 2))
    return bytes(ba)

def hamming(a: List[int], b: List[int]) -> int:
    return sum(x != y for x, y in zip(a, b))

@router.post("/login-auth")
async def login_auth(payload: dict):
    # 1) load everything

    ok=True
    status_code=[]
    message=[]
    if not (SETUP_PATH.exists() and REG_PATH.exists() and SMARTCARD_PATH.exists()):
        ok=False
        status_code.append(500)
        message.append("Not initialized")

    setup = json.loads(SETUP_PATH.read_text())
    reg   = json.loads(REG_PATH.read_text())
    card  = json.loads(SMARTCARD_PATH.read_text())

    n, m = setup["n"], setup["m"]
    A, mk, pk = setup["A"], setup["mk"], setup["pk"]
    ID_i = payload.get("ID_i")
    B_i  = payload.get("B_i")
    N_u_hex  = payload.get("N_u_hex", "")

    try:
        N_u = bytes.fromhex(N_u_hex)
    except Exception:
        N_u = b""
    if ID_i!=reg["ID_i"] or not isinstance(B_i,list) or len(B_i)!=384:
        ok=False
        status_code.append(400)
        message.append("Invalid credentials")

    # 2) Client: recompute w (no fresh noise)
    t1=time.perf_counter()
    v_i      = card["v_i"]
    w_client = [sum(A[i][j]&v_i[j] for j in range(n)) & 1 for i in range(m)]

    # 3) Client: form beta_q = w ⊕ (x_q‖0)
    x_q    = B_i + [0]*(512-384)
    b_q    = x_q + [0]*128
    beta_q = [(w_client[i] ^ b_q[i]) for i in range(m)]

    # --- interactive step ---
    # Server recovers w_srv = Z_i ⊕ pk
    Z_i   = reg["Z_i"]
    w_srv = [(Z_i[i] ^ pk[i]) for i in range(m)]

    # 4) Client: recover b_rec = beta_r ⊕ w_srv ⊕ e
    beta_r = card["beta_r"]
    e       = card["e"]
    b_rec   = [(beta_r[i] ^ w_srv[i] ^ e[i]) for i in range(m)]

    # split out biometric and key
    x_r_rec = b_rec[:384]
    k_i_rec = b_rec[384:]   # only for session key

    # 5) biometric check
    if hamming(x_r_rec, B_i) > 32:
        ok=False
        status_code.append(401)
        message.append("Biometric mismatch")

    # 6) **Use stored** k_i and N to recompute c_i
    k_i_list = card.get("k_i")
    N_list   = card.get("N")
    if not k_i_list or not N_list:
        ok=False
        status_code.append(500)
        message.append("Smart-card missing k_i or N")
        
    c_i_input    = bits_to_bytes(k_i_list + N_list)
    recomputed_ci= hashlib.sha3_256(c_i_input).digest()

    # load stored c_i
    stored_ci_hex = reg.get("c_i")
    if not stored_ci_hex:
        ok=False
        status_code.append(500)
        message.append("Server record missing c_i")
    stored_ci = bytes.fromhex(stored_ci_hex)

    # compare
    if not hmac.compare_digest(recomputed_ci, stored_ci):
        ok=False
        status_code.append(401)
        message.append("Key/nonce binding failed (c_i mismatch)")

    # 7) now verify r_i = H(c_i || beta_r)
    r_ip = hashlib.sha3_256(stored_ci + bits_to_bytes(beta_r)).digest()
    if not hmac.compare_digest(r_ip,bytes.fromhex(reg["r_i"])):
        ok=False
        status_code.append(401)
        message.append("Key/nonce binding failed (c_i mismatch)")

    # 8) Client computes proof-of-knowledge of r_i:
    theta1 = hmac.new(
        key=bits_to_bytes(mk),
        msg=ID_i.encode() + r_ip,
        digestmod=hashlib.sha3_256
    ).digest()

    # send {ID_i, beta_q, theta1} to server

    # 9) Server re-computes HMAC(ID_i||r_i) and compares
    expected = hmac.new(
        key=bits_to_bytes(mk),
        msg=ID_i.encode() + bytes.fromhex(reg["r_i"]),
        digestmod=hashlib.sha3_256
    ).digest()
    if not hmac.compare_digest(expected,theta1):
        ok=False
        status_code.append(401)
        message.append("Server proof-of-knowledge failed")

    user_seen = SEEN_NONCES.setdefault(ID_i, set())
    if N_u in user_seen:
        ok = False
        status_code.append(425)
        message.append("Possible replay attack")
    else:
        # Only mark it “used” if all previous checks passed so far
        if ok:
            user_seen.add(N_u)
    
    # derive session key from recovered k_i_rec
    # server nonce + theta3
    N_s    = [random.getrandbits(1) for _ in range(128)]
    theta3 = hashlib.sha3_256(theta1 + bits_to_bytes(N_s)).digest()
    # client verifies theta3
    theta3p= hashlib.sha3_256(theta1 + bits_to_bytes(N_s)).digest()
    if not hmac.compare_digest(theta3,theta3p):
        ok=False
        status_code.append(401)
        message.append("Server authenticity failed")


    K_sess= hashlib.sha3_256(bits_to_bytes(k_i_rec) + N_u + bits_to_bytes(N_s)).digest()
    t2=time.perf_counter()
    T=t2-t1
    print(f"Time for login-auth:{T:.6f} seconds")
    if not ok:
        sc=status_code[0]
        m=message[0]
        raise HTTPException(sc,m)
    return {
        "message":     "Login successful",
        "theta3":      theta3.hex(),
        "N_s":         bits_to_bytes(N_s).hex(),
        "session_key": K_sess.hex()
    }
