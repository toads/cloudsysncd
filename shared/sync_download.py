#!/usr/bin/env python3
"""
syncd auto-downloader
通过 PIN 配对协商密钥，定期轮询自动下载新文件。

用法: python3 sync_download.py [--interval 60] [--dir ./downloads]
"""

import os
import sys
import json
import time
import hmac
import hashlib
import argparse
import ssl
import io
import tarfile

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    print("需要安装: pip install requests")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
except ImportError:
    print("需要安装: pip install cryptography")
    sys.exit(1)


SERVER = os.environ.get("SYNCD_SERVER", "https://kc.toads.ink")
STATE_FILE = ".syncd_state.json"

# 全局 session，复用连接 + 统一 headers
session = requests.Session()
session.verify = False  # 跳过证书校验（内网中间人代理）
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "application/json",
})
# 禁用 InsecureRequestWarning
requests.packages.urllib3.disable_warnings()


# ============ Crypto Helpers ============

def hex_to_bytes(h):
    return bytes.fromhex(h)


def bytes_to_hex(b):
    return b.hex()


def aes_decrypt(key_bytes, iv_hex, ciphertext_hex, tag_hex):
    iv = hex_to_bytes(iv_hex)
    ct = hex_to_bytes(ciphertext_hex)
    tag = hex_to_bytes(tag_hex)
    return AESGCM(key_bytes).decrypt(iv, ct + tag, None)


def do_hkdf(ikm, salt_str, info_str, length=32):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt_str.encode(),
        info=info_str.encode(),
    ).derive(ikm)


def do_hmac(key_bytes, data_str):
    return hmac.new(key_bytes, data_str.encode(), hashlib.sha256).hexdigest()


def api_get(path):
    url = f"{SERVER}{path}"
    r = session.get(url, timeout=15)
    if not r.ok:
        raise Exception(f"GET {path} → {r.status_code}\n  Headers: {dict(r.headers)}\n  Body: {r.text[:200]}")
    return r.json()


def api_post(path, body):
    url = f"{SERVER}{path}"
    r = session.post(url, json=body, timeout=15)
    if not r.ok:
        raise Exception(f"POST {path} → {r.status_code}\n  Body: {r.text[:200]}")
    return r.json()


# ============ ECDH + PIN Pairing ============

def pair_with_pin(pin):
    """通过 PIN 完成 ECDH 密钥协商，返回 master key bytes"""
    # 1. 获取服务端公钥
    init = api_get("/api/pair/init")
    server_pub_hex = init["serverPublicKey"]

    # 2. 生成客户端 ECDH 密钥对
    private_key = ec.generate_private_key(ec.SECP256R1())
    client_pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    client_pub_hex = bytes_to_hex(client_pub_bytes)

    # 3. 计算共享密钥
    server_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), hex_to_bytes(server_pub_hex)
    )
    shared_secret = private_key.exchange(ec.ECDH(), server_pub_key)

    # 4. 派生 auth key，生成 proof
    auth_key = do_hkdf(shared_secret, "syncd-auth", "pin-verify")
    proof = do_hmac(auth_key, pin)

    # 5. 发送验证请求
    device_id = f"python-{bytes_to_hex(os.urandom(4))}"
    result = api_post("/api/pair/verify", {
        "clientPublicKey": client_pub_hex,
        "proof": proof,
        "deviceId": device_id,
    })

    # 6. 验证服务端 proof
    expected = do_hmac(auth_key, "server-confirmed")
    if result["serverProof"] != expected:
        raise Exception("服务端验证失败")

    # 7. 解密 master key
    transport_key = do_hkdf(
        shared_secret, "syncd-transport", "master-key-delivery"
    )
    emk = result["encryptedMasterKey"]
    master_key = aes_decrypt(
        transport_key, emk["iv"], emk["ciphertext"], emk["tag"]
    )

    print(f"  配对成功 (device: {device_id})")
    return master_key


# ============ Key Management ============

def get_key(download_dir):
    key_file = os.path.join(download_dir, ".syncd_key")
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            return hex_to_bytes(f.read().strip())

    pin = input("输入 PIN 码: ").strip()
    if len(pin) != 6 or not pin.isdigit():
        print("PIN 应为 6 位数字")
        sys.exit(1)

    master_key = pair_with_pin(pin)

    with open(key_file, "w") as f:
        f.write(bytes_to_hex(master_key))
    os.chmod(key_file, 0o600)
    return master_key


# ============ Batch Download ============

def batch_download(key, download_dir, since=None):
    """调用 /api/batch 批量下载，返回 (文件数, 总大小)"""
    url = "/api/batch"
    if since:
        url += f"?since={since}"

    data = api_get(url)
    count = data.get("count", 0)
    total_size = data.get("totalSize", 0)

    if count == 0 or data.get("encrypted") is None:
        return 0, 0

    enc = data["encrypted"]
    archive = aes_decrypt(key, enc["iv"], enc["ciphertext"], enc["tag"])

    # 解压 tar.gz 到目标目录
    buf = io.BytesIO(archive)
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        tf.extractall(path=download_dir)

    return count, total_size


def format_size(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n/1024:.1f} KB"
    return f"{n/1024/1024:.1f} MB"


# ============ Main ============

def load_state(p):
    if os.path.exists(p):
        with open(p, "r") as f:
            return json.load(f)
    return {"last_sync": None}


def save_state(p, s):
    with open(p, "w") as f:
        json.dump(s, f, indent=2)


def poll_once(key, download_dir, state, state_path):
    since = state.get("last_sync")
    try:
        count, total_size = batch_download(key, download_dir, since=since)
    except Exception as e:
        print(f"  [!] 批量下载失败: {e}")
        return 0

    if count > 0:
        state["last_sync"] = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        save_state(state_path, state)
        print(f"  + {count} 个文件 ({format_size(total_size)})")
    return count


def main():
    parser = argparse.ArgumentParser(description="syncd 自动下载")
    parser.add_argument("--interval", type=int, default=60, help="轮询间隔秒")
    parser.add_argument("--dir", default=".", help="下载目录")
    parser.add_argument("--once", action="store_true", help="只执行一次")
    args = parser.parse_args()

    download_dir = os.path.abspath(args.dir)
    os.makedirs(download_dir, exist_ok=True)

    state_path = os.path.join(download_dir, STATE_FILE)
    state = load_state(state_path)
    key = get_key(download_dir)

    print(f"syncd downloader")
    print(f"  服务器: {SERVER}")
    print(f"  目录: {download_dir}")
    print(f"  间隔: {args.interval}s\n")

    while True:
        ts = time.strftime("%H:%M:%S")
        n = poll_once(key, download_dir, state, state_path)
        if n:
            print(f"[{ts}] 下载了 {n} 个新文件")
        else:
            print(f"[{ts}] 无新文件", end="\r")
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
