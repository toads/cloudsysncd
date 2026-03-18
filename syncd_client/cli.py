#!/usr/bin/env python3
"""
cloudsysncd auto-downloader
通过 PIN 配对协商密钥，定期轮询自动下载新文件。
"""

import argparse
import io
import json
import os
import sys
import time
import hmac
import socket
import hashlib
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


DEFAULT_SERVER = os.environ.get("SYNCD_SERVER", "http://127.0.0.1:21891")
STATE_FILE = ".syncd_state.json"
KEY_FILE = ".syncd_key"

session = requests.Session()
session.headers.update({
    "User-Agent": "cloudsysncd-python-client/1.0",
    "Accept": "application/json",
})

CONFIG = {
    "server": DEFAULT_SERVER.rstrip("/"),
    "verify_tls": False,
    "retry_base": 2.0,
    "retry_max": 20.0,
    "retry_attempts": 4,
}


def log(message):
    print(message, flush=True)


def hex_to_bytes(value):
    return bytes.fromhex(value)


def bytes_to_hex(value):
    return value.hex()


def resolve_server_url(path):
    return f"{CONFIG['server']}{path}"


def should_verify_tls(server, cli_value, insecure):
    if cli_value:
        return True
    if insecure:
        return False

    env_value = os.environ.get("SYNCD_VERIFY_TLS")
    if env_value is not None:
        return env_value.strip().lower() in {"1", "true", "yes", "on"}

    return not server.startswith("http://")


def format_size(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 / 1024:.1f} MB"


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


def build_default_device_name():
    return f"{socket.gethostname()}-python"


def aes_decrypt(key_bytes, iv_hex, ciphertext_hex, tag_hex):
    iv = hex_to_bytes(iv_hex)
    ciphertext = hex_to_bytes(ciphertext_hex)
    tag = hex_to_bytes(tag_hex)
    return AESGCM(key_bytes).decrypt(iv, ciphertext + tag, None)


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
        raise RuntimeError("缺少 device_id，请重新配对")

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


def should_retry(response=None, error=None):
    if error is not None:
        return True
    if response is None:
        return False
    return response.status_code in {429, 500, 502, 503, 504}


def request_with_retry(method, path, timeout=15, **kwargs):
    url = resolve_server_url(path)
    last_error = None
    response = None

    for attempt in range(CONFIG["retry_attempts"]):
        error = None
        response = None
        try:
            response = session.request(method, url, timeout=timeout, verify=CONFIG["verify_tls"], **kwargs)
            if not should_retry(response=response):
                return response
            last_error = RuntimeError(f"{method} {path} -> HTTP {response.status_code}")
        except requests.RequestException as exc:
            error = exc
            last_error = exc

        if attempt >= CONFIG["retry_attempts"] - 1 or not should_retry(response=response, error=error):
            break

        delay = min(CONFIG["retry_max"], CONFIG["retry_base"] * (2 ** attempt))
        if response is not None:
            detail = f"HTTP {response.status_code}"
        else:
            detail = str(error)
        log(f"  [retry] {method} {path} 失败 ({detail})，{delay:.1f}s 后重试")
        time.sleep(delay)

    if isinstance(last_error, requests.RequestException):
        raise RuntimeError(f"{method} {path} 请求失败: {last_error}") from last_error
    if response is not None:
        return response
    raise RuntimeError(f"{method} {path} 请求失败")


def expect_json(response, path, method):
    text = response.text
    if not response.ok:
        raise RuntimeError(f"{method} {path} -> {response.status_code}\n  Body: {text[:240]}")
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(f"{method} {path} 返回了非 JSON 数据") from exc


def api_get(path, auth_key=None, device_id=None):
    headers = build_auth_headers("GET", path, b"", auth_key, device_id) if auth_key else None
    response = request_with_retry("GET", path, headers=headers)
    return expect_json(response, path, "GET")


def api_post(path, body, auth_key=None, device_id=None):
    body_bytes = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    headers = {
        "Content-Type": "application/json",
    }
    if auth_key:
        headers.update(build_auth_headers("POST", path, body_bytes, auth_key, device_id))
    response = request_with_retry("POST", path, data=body_bytes, headers=headers)
    return expect_json(response, path, "POST")


def api_get_response(path, timeout=60, auth_key=None, device_id=None):
    headers = build_auth_headers("GET", path, b"", auth_key, device_id) if auth_key else None
    response = request_with_retry("GET", path, headers=headers, timeout=timeout, stream=True)
    if response.status_code == 204:
        return response
    if not response.ok:
        snippet = response.text[:240]
        response.close()
        raise RuntimeError(f"GET {path} -> {response.status_code}\n  Body: {snippet}")
    return response


def pair_with_pin(pin, device_name):
    init = api_get("/api/pair/init")
    server_pub_hex = init["serverPublicKey"]

    private_key = ec.generate_private_key(ec.SECP256R1())
    client_pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    client_pub_hex = bytes_to_hex(client_pub_bytes)

    server_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        hex_to_bytes(server_pub_hex),
    )
    shared_secret = private_key.exchange(ec.ECDH(), server_pub_key)

    auth_key = do_hkdf(shared_secret, "syncd-auth", "pin-verify")
    proof = do_hmac(auth_key, pin)

    device_id = f"python-{bytes_to_hex(os.urandom(4))}"
    result = api_post("/api/pair/verify", {
        "clientPublicKey": client_pub_hex,
        "proof": proof,
        "deviceId": device_id,
        "deviceName": device_name,
        "deviceType": "python",
    })

    expected = do_hmac(auth_key, "server-confirmed")
    if result["serverProof"] != expected:
        raise RuntimeError("服务端验证失败")

    transport_key = do_hkdf(shared_secret, "syncd-transport", "master-key-delivery")
    encrypted_master_key = result["encryptedMasterKey"]
    master_key = aes_decrypt(
        transport_key,
        encrypted_master_key["iv"],
        encrypted_master_key["ciphertext"],
        encrypted_master_key["tag"],
    )
    log(f"  配对成功 (device: {device_id}, name: {device_name})")
    return master_key, device_id


def load_state(state_path):
    state = {"last_sync": None, "last_sync_ms": None, "device_id": None, "device_name": None}
    if os.path.exists(state_path):
        with open(state_path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
            if isinstance(loaded, dict):
                state.update(loaded)

    cursor = parse_sync_cursor(state.get("last_sync_ms"))
    if cursor is None:
        cursor = parse_sync_cursor(state.get("last_sync"))
    state["last_sync_ms"] = cursor
    state["last_sync"] = format_sync_cursor(cursor) if cursor is not None else None
    return state


def save_state(state_path, state):
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, ensure_ascii=False)


def get_key(state_dir, state, state_path, device_name):
    key_path = os.path.join(state_dir, KEY_FILE)
    device_id = state.get("device_id")
    if os.path.exists(key_path) and device_id:
        with open(key_path, "r", encoding="utf-8") as handle:
            return hex_to_bytes(handle.read().strip()), device_id

    if os.path.exists(key_path) and not device_id:
        log("检测到旧版客户端状态，缺少 device_id，需要重新配对一次。")

    pin = input("输入 PIN 码: ").strip()
    if len(pin) != 6 or not pin.isdigit():
        raise RuntimeError("PIN 应为 6 位数字")

    master_key, device_id = pair_with_pin(pin, device_name)
    os.makedirs(state_dir, exist_ok=True)
    with open(key_path, "w", encoding="utf-8") as handle:
        handle.write(bytes_to_hex(master_key))
    os.chmod(key_path, 0o600)

    state["device_id"] = device_id
    state["device_name"] = device_name
    save_state(state_path, state)
    return master_key, device_id


def safe_extract_tar(tar_file, download_dir):
    root = os.path.realpath(download_dir)
    for member in tar_file.getmembers():
        member_path = os.path.realpath(os.path.join(download_dir, member.name))
        if member_path != root and not member_path.startswith(root + os.sep):
            raise RuntimeError(f"归档包含非法路径: {member.name}")
    tar_file.extractall(path=download_dir)


def write_response_to_file(response, target_path):
    with open(target_path, "wb") as handle:
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            if chunk:
                handle.write(chunk)


def decrypt_gcm_file(key_bytes, iv_hex, encrypted_path, output_path):
    encrypted_size = os.path.getsize(encrypted_path)
    if encrypted_size < 16:
        raise RuntimeError("批量下载响应过短，无法提取 GCM tag")

    iv = hex_to_bytes(iv_hex)
    ciphertext_size = encrypted_size - 16
    with open(encrypted_path, "rb") as source:
        source.seek(ciphertext_size)
        tag = source.read(16)
        source.seek(0)

        decryptor = Cipher(
            algorithms.AES(key_bytes),
            modes.GCM(iv, tag),
        ).decryptor()

        remaining = ciphertext_size
        with open(output_path, "wb") as handle:
            while remaining > 0:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise RuntimeError("批量下载密文读取中断")
                remaining -= len(chunk)
                handle.write(decryptor.update(chunk))

            handle.write(decryptor.finalize())


def batch_download(key, download_dir, device_id, since=None):
    path = "/api/batch"
    if since is not None:
        path += f"?since={since}"

    response = api_get_response(path, auth_key=key, device_id=device_id)
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

                with tarfile.open(archive_path, mode="r:gz") as tar_handle:
                    safe_extract_tar(tar_handle, download_dir)

            return count, total_size, snapshot_at

        data = response.json()
        count = data.get("count", 0)
        total_size = data.get("totalSize", 0)
        if count == 0 or data.get("encrypted") is None:
            return 0, 0, snapshot_at

        encrypted = data["encrypted"]
        archive = aes_decrypt(key, encrypted["iv"], encrypted["ciphertext"], encrypted["tag"])
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar_handle:
            safe_extract_tar(tar_handle, download_dir)
        return count, total_size, snapshot_at
    finally:
        response.close()


def poll_once(key, device_id, download_dir, state, state_path):
    since = state.get("last_sync_ms")
    count, total_size, snapshot_at = batch_download(key, download_dir, device_id, since=since)
    if count > 0:
        cursor = snapshot_at if snapshot_at is not None else int(time.time() * 1000)
        state["last_sync_ms"] = cursor
        state["last_sync"] = format_sync_cursor(cursor)
        save_state(state_path, state)
        log(f"  + {count} 个文件 ({format_size(total_size)})")
    return count


def main():
    parser = argparse.ArgumentParser(description="cloudsysncd 自动下载")
    parser.add_argument("--interval", type=int, default=60, help="轮询间隔秒")
    parser.add_argument("--dir", default=".", help="下载目录")
    parser.add_argument("--state-dir", default=None, help="状态目录，默认与下载目录相同")
    parser.add_argument("--once", action="store_true", help="只执行一次")
    parser.add_argument("--device-name", default=None, help="配对时写入的设备名称")
    parser.add_argument("--retry-base", type=float, default=2.0, help="失败后重试的基础等待秒数")
    parser.add_argument("--retry-max", type=float, default=20.0, help="失败后重试的最大等待秒数")
    tls_group = parser.add_mutually_exclusive_group()
    tls_group.add_argument("--verify-tls", action="store_true", help="强制开启 TLS 证书校验")
    tls_group.add_argument("--insecure", action="store_true", help="关闭 TLS 证书校验")
    args = parser.parse_args()

    server = DEFAULT_SERVER.rstrip("/")
    CONFIG["server"] = server
    CONFIG["verify_tls"] = should_verify_tls(server, args.verify_tls, args.insecure)
    CONFIG["retry_base"] = max(args.retry_base, 0.1)
    CONFIG["retry_max"] = max(args.retry_max, CONFIG["retry_base"])
    if not CONFIG["verify_tls"]:
        requests.packages.urllib3.disable_warnings()

    download_dir = os.path.abspath(args.dir)
    state_dir = os.path.abspath(args.state_dir or download_dir)
    os.makedirs(download_dir, exist_ok=True)
    os.makedirs(state_dir, exist_ok=True)

    state_path = os.path.join(state_dir, STATE_FILE)
    state = load_state(state_path)
    device_name = (args.device_name or state.get("device_name") or build_default_device_name()).strip()[:80]

    key, device_id = get_key(state_dir, state, state_path, device_name)

    log("cloudsysncd downloader")
    log(f"  服务器: {CONFIG['server']}")
    log(f"  下载目录: {download_dir}")
    log(f"  状态目录: {state_dir}")
    log(f"  设备名称: {device_name}")
    log(f"  TLS 校验: {'开启' if CONFIG['verify_tls'] else '关闭'}")
    log(f"  轮询间隔: {args.interval}s")
    log("")

    while True:
        ts = time.strftime("%H:%M:%S")
        try:
            count = poll_once(key, device_id, download_dir, state, state_path)
            if count:
                log(f"[{ts}] 下载了 {count} 个新文件")
            else:
                log(f"[{ts}] 无新文件")
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            message = str(exc)
            if "Unknown device" in message or "Not paired" in message:
                log("  [!] 当前设备已被撤销或服务端状态已失效，请删除状态目录中的 .syncd_key 后重新运行。")
            else:
                log(f"  [!] 批量下载失败: {message}")

        if args.once:
            break
        time.sleep(max(args.interval, 1))


def run():
    try:
        main()
    except KeyboardInterrupt:
        log("\n已停止。")
        sys.exit(130)
    except Exception as exc:
        log(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    run()
