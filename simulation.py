import time
import hmac
import hashlib
import math
import requests


DRAND_BASE = "https://api.drand.sh"
LATEST_URL = f"{DRAND_BASE}/public/latest"
ROUND_URL_TEMPLATE = f"{DRAND_BASE}/public/{{round}}"



def fetch_beacon(round_num=None):
    if round_num is None:
        url = LATEST_URL
    else:
        url = ROUND_URL_TEMPLATE.format(round=round_num)
    r = requests.get(url)
    r.raise_for_status()
    data = r.json()
    return data  # contains 'round','randomness','signature','previous'


def compute_hotp(key: bytes, counter: bytes, digits=6):
    digest = hmac.new(key, counter, hashlib.sha256).digest()
    offset = digest[-1] & 0x0F
    code = int.from_bytes(digest[offset:offset+4], "big") & 0x7fffffff
    return code % (10**digits)

def generate_e2totp(K: bytes, T0: int, T_curr: int, X: int, delta: int, is_client: bool):
    t_step = (T_curr - T0) // X
    if is_client:
        b = fetch_beacon()
        counter = t_step.to_bytes(8, 'big') + bytes.fromhex(b["randomness"])
        otp = compute_hotp(K, counter)
        return [(b["round"], otp)]
    else:
        n = math.ceil(X / delta)
        latest = fetch_beacon()
        results = []
        round_latest = latest["round"]
        for i in range(n):
            rnum = round_latest - i
            b = fetch_beacon(rnum)
            ctr = t_step.to_bytes(8, 'big') + bytes.fromhex(b["randomness"])
            otp = compute_hotp(K, ctr)
            results.append((b["round"], otp))
        return results

def main():
    K = b"supersecretsharedkey"
    T0 = 0
    X = 60
    delta = 30
    T_curr = int(time.time())
    print("CLIENT E2TOTP:")
    client = generate_e2totp(K, T0, T_curr, X, delta, True)
    print(client)
    print("\nSERVER E2TOTP candidates:")
    server = generate_e2totp(K, T0, T_curr, X, delta, False)
    print(server)

if __name__ == "__main__":
    main()
