#!/usr/bin/env python3
"""
cloudsysncd auto-downloader
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
import io
import tarfile
import tempfile
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("需要安装: pip install requests")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
except ImportError:
    print("需要安装: pip install cryptography")
    sys.exit(1)


SERVER = os.environ.get("SYNCD_SERVER", "http://127.0.0.1:21891")
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


def aes_decrypt_bytes(key_bytes, iv_hex, ciphertext, tag):
    return AESGCM(key_bytes).decrypt(hex_to_bytes(iv_hex), ciphertext + tag, None)


def do_hkdf(ikm, salt_str, info_str, length=32):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt_str.encode(),
        info=info_str.encode(),
    ).derive(ikm)


def do_hmac(key_bytes, data_str):
    return hmac.new(key_bytes, data_str.encode(), hashlib.sha256).hexdigest()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def derive_request_auth_key(master_key, device_id):
    return do_hkdf(master_key, "syncd-request-auth", f"device:{device_id}")


def build_auth_headers(method, path, body_bytes, master_key, device_id):
    if not device_id:
        raise Exception("缺少 device_id，请重新配对")

    timestamp = str(int(time.time() * 1000))
    nonce = bytes_to_hex(os.urandom(16))
    body_hash = sha256_hex(body_bytes)
    signature = do_hmac(
        derive_request_auth_key(master_key, device_id),
        "\n".join([method.upper(), path, timestamp, nonce, body_hash]),
    )
    return {
        "X-Device-Id": device_id,
        "X-Auth-Timestamp": timestamp,
        "X-Auth-Nonce": nonce,
        "X-Auth-Signature": signature,
    }


def api_get(path, auth_key=None, device_id=None):
    url = f"{SERVER}{path}"
    headers = build_auth_headers("GET", path, b"", auth_key, device_id) if auth_key else None
    r = session.get(url, timeout=15, headers=headers)
    if not r.ok:
        raise Exception(f"GET {path} → {r.status_code}\n  Headers: {dict(r.headers)}\n  Body: {r.text[:200]}")
    return r.json()


def api_post(path, body, auth_key=None, device_id=None):
    url = f"{SERVER}{path}"
    body_bytes = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    headers = {
        "Content-Type": "application/json",
    }
    if auth_key:
        headers.update(build_auth_headers("POST", path, body_bytes, auth_key, device_id))
    r = session.post(url, data=body_bytes, headers=headers, timeout=15)
    if not r.ok:
        raise Exception(f"POST {path} → {r.status_code}\n  Body: {r.text[:200]}")
    return r.json()


def api_get_response(path, timeout=60, auth_key=None, device_id=None):
    url = f"{SERVER}{path}"
    headers = build_auth_headers("GET", path, b"", auth_key, device_id) if auth_key else None
    r = session.get(url, timeout=timeout, headers=headers, stream=True)
    if r.status_code == 204:
        return r
    if not r.ok:
        raise Exception(f"GET {path} → {r.status_code}\n  Headers: {dict(r.headers)}\n  Body: {r.text[:200]}")
    return r


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
    return master_key, device_id


# ============ Key Management ============

def get_key(download_dir, state, state_path):
    key_file = os.path.join(download_dir, ".syncd_key")
    device_id = state.get("device_id")
    if os.path.exists(key_file) and device_id:
        with open(key_file, "r") as f:
            return hex_to_bytes(f.read().strip()), device_id

    if os.path.exists(key_file) and not device_id:
        print("检测到旧版客户端状态，缺少 device_id，需要重新配对一次。")

    pin = input("输入 PIN 码: ").strip()
    if len(pin) != 6 or not pin.isdigit():
        print("PIN 应为 6 位数字")
        sys.exit(1)

    master_key, device_id = pair_with_pin(pin)

    with open(key_file, "w") as f:
        f.write(bytes_to_hex(master_key))
    os.chmod(key_file, 0o600)
    state["device_id"] = device_id
    save_state(state_path, state)
    return master_key, device_id


# ============ Batch Download ============

def batch_download(key, download_dir, device_id, since=None):
    """调用 /api/batch 批量下载，返回 (文件数, 总大小, 快照时间戳ms)"""
    url = "/api/batch"
    if since is not None:
        url += f"?since={since}"

    response = api_get_response(url, auth_key=key, device_id=device_id)
    try:
        if response.status_code == 204:
            return 0, 0, None

        snapshot_at = parse_sync_cursor(response.headers.get("X-Batch-Snapshot-At"))
        iv_hex = response.headers.get("X-Encrypted-IV")
        if iv_hex:
            count = int(response.headers.get("X-Batch-Count", "0"))
            total_size = int(response.headers.get("X-Batch-Total-Size", "0"))

            with tempfile.TemporaryDirectory(prefix="cloudsysncd-batch-") as temp_dir:
                encrypted_path = os.path.join(temp_dir, "batch.enc")
                archive_path = os.path.join(temp_dir, "batch.tar.gz")
                write_response_to_file(response, encrypted_path)
                decrypt_gcm_file(key, iv_hex, encrypted_path, archive_path)

                with tarfile.open(archive_path, mode="r:gz") as tf:
                    safe_extract_tar(tf, download_dir)

            return count, total_size, snapshot_at

        data = response.json()
        count = data.get("count", 0)
        total_size = data.get("totalSize", 0)

        if count == 0 or data.get("encrypted") is None:
            return 0, 0, snapshot_at

        enc = data["encrypted"]
        archive = aes_decrypt(key, enc["iv"], enc["ciphertext"], enc["tag"])

        buf = io.BytesIO(archive)
        with tarfile.open(fileobj=buf, mode="r:gz") as tf:
            safe_extract_tar(tf, download_dir)

        return count, total_size, snapshot_at
    finally:
        response.close()


def format_size(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n/1024:.1f} KB"
    return f"{n/1024/1024:.1f} MB"


def safe_extract_tar(tf, download_dir):
    root = os.path.realpath(download_dir)
    for member in tf.getmembers():
        member_path = os.path.realpath(os.path.join(download_dir, member.name))
        if member_path != root and not member_path.startswith(root + os.sep):
            raise Exception(f"归档包含非法路径: {member.name}")
    tf.extractall(path=download_dir)


def write_response_to_file(response, target_path):
    with open(target_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk)


def decrypt_gcm_file(key_bytes, iv_hex, encrypted_path, output_path):
    encrypted_size = os.path.getsize(encrypted_path)
    if encrypted_size < 16:
        raise Exception("批量下载响应过短，无法提取 GCM tag")

    iv = hex_to_bytes(iv_hex)
    ciphertext_size = encrypted_size - 16
    with open(encrypted_path, "rb") as src:
        src.seek(ciphertext_size)
        tag = src.read(16)
        src.seek(0)

        decryptor = Cipher(
            algorithms.AES(key_bytes),
            modes.GCM(iv, tag),
        ).decryptor()

        remaining = ciphertext_size
        with open(output_path, "wb") as out:
            while remaining > 0:
                chunk = src.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise Exception("批量下载密文读取中断")
                remaining -= len(chunk)
                out.write(decryptor.update(chunk))

            out.write(decryptor.finalize())


# ============ Main ============

def load_state(p):
    state = {"last_sync": None, "last_sync_ms": None, "device_id": None}
    if os.path.exists(p):
        with open(p, "r") as f:
            loaded = json.load(f)
            if isinstance(loaded, dict):
                state.update(loaded)

    cursor = parse_sync_cursor(state.get("last_sync_ms"))
    if cursor is None:
        cursor = parse_sync_cursor(state.get("last_sync"))
    state["last_sync_ms"] = cursor
    state["last_sync"] = format_sync_cursor(cursor) if cursor is not None else None
    return state


def save_state(p, s):
    with open(p, "w") as f:
        json.dump(s, f, indent=2)


def poll_once(key, device_id, download_dir, state, state_path):
    since = state.get("last_sync_ms")
    try:
        count, total_size, snapshot_at = batch_download(key, download_dir, device_id, since=since)
    except Exception as e:
        print(f"  [!] 批量下载失败: {e}")
        return 0

    if count > 0:
        cursor = snapshot_at if snapshot_at is not None else int(time.time() * 1000)
        state["last_sync_ms"] = cursor
        state["last_sync"] = format_sync_cursor(cursor)
        save_state(state_path, state)
        print(f"  + {count} 个文件 ({format_size(total_size)})")
    return count


def parse_sync_cursor(value):
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return int(value)

    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return int(text)

    try:
        return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def format_sync_cursor(timestamp_ms):
    if timestamp_ms is None:
        return None
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def main():
    parser = argparse.ArgumentParser(description="cloudsysncd 自动下载")
    parser.add_argument("--interval", type=int, default=60, help="轮询间隔秒")
    parser.add_argument("--dir", default=".", help="下载目录")
    parser.add_argument("--once", action="store_true", help="只执行一次")
    args = parser.parse_args()

    download_dir = os.path.abspath(args.dir)
    os.makedirs(download_dir, exist_ok=True)

    state_path = os.path.join(download_dir, STATE_FILE)
    state = load_state(state_path)
    key, device_id = get_key(download_dir, state, state_path)

    print("cloudsysncd downloader")
    print(f"  服务器: {SERVER}")
    print(f"  目录: {download_dir}")
    print(f"  间隔: {args.interval}s\n")

    while True:
        ts = time.strftime("%H:%M:%S")
        n = poll_once(key, device_id, download_dir, state, state_path)
        if n:
            print(f"[{ts}] 下载了 {n} 个新文件")
        else:
            print(f"[{ts}] 无新文件", end="\r")
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
