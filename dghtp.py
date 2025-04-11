#!/usr/bin/env python3
"""
DGHTP - DiamondGotCat Hypertext Transfer Protocol
このプロトコルは、DGCTP の設計を応用し、セキュアな HTTP 代替としてリクエスト／レスポンス処理を実現する実験的プロトコルです。

【プロトコル仕様】
--- リクエストヘッダー ---
#!DGHTP START
#!VERSION    1.0
#!METHOD     GET           # または POST
#!PATH       /index.html   # 取得するパス（GET）またはアップロード先（POST）
#!ENCRYPT    1             # 暗号化ありの場合は 1、なければ 0
#!COMPRESS   0             # 圧縮ありの場合は 1、なければ 0
#!CONTENT-LENGTH  12345    # 平文でのボディ長（バイト）
#!DGHTP END

ヘッダー送信後、ENCRYPT が 1 の場合は、ランダムな 16 バイトのソルトと 16 バイトの IV を送信します。  
その後、ボディはチャンクごとに以下の形式で送信します：

【各チャンク】
- 先頭 8 バイトでチャンク（変換後）のバイト長（big-endian 整数）
- 続いてチャンクデータ

チャンク変換については、以下の順序で処理されます。  
【送信側】
  Plaintext → (圧縮処理 ※ONの場合) → (暗号化処理 ※ONの場合) → チャンク送信  
【受信側】
  受信チャンク → (暗号化解除 ※ONの場合) → (圧縮解除 ※ONの場合) → Plaintext復元

※ 各方向は個別の暗号化・復号化インスタンスを用います。
"""

import asyncio
import socket
import os
import sys
import argparse
import zstandard as zstd  # zstd による圧縮／解凍
import getpass
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

DGHTP_VERSION = "1.0"
CHUNK_SIZE = 1024 * 1024  # 1MB 単位で転送（用途に応じて調整可）

# 暗号化に関する定数設定（AES-256・CFBモード）
KEY_LENGTH = 32    # AES-256用キー
IV_LENGTH = 16     # 128-bit IV
SALT_LENGTH = 16   # 128-bit ソルト
ITERATIONS = 100_000  # PBKDF2 イテレーション

def derive_key(password: str, salt: bytes) -> bytes:
    """
    パスワードとソルトから AES-256 用キーを導出します。
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

async def read_dghtp_header(reader: asyncio.StreamReader) -> dict:
    """
    DGHTP ヘッダーを受信し、辞書形式にパースして返します。
    ヘッダーは、行ごとに "#!KEY   VALUE" 形式となり、先頭が
    "#!DGHTP START"、末尾が "#!DGHTP END" のマーカーにより囲まれます。
    """
    header_data = {}
    # 最初の行が START であることを確認
    line = (await reader.readline()).decode().strip()
    if line != "#!DGHTP START":
        raise ValueError("Invalid DGHTP header start.")
    # ヘッダー行を読み込む
    while True:
        line = (await reader.readline()).decode().strip()
        if line == "#!DGHTP END":
            break
        if line.startswith("#!"):
            try:
                # スペース区切りでキーと値を抽出
                parts = line[2:].split(None, 1)
                if len(parts) == 2:
                    key, value = parts
                    header_data[key.upper()] = value
            except Exception:
                continue
    return header_data

def build_dghtp_header(metadata: dict) -> bytes:
    """
    metadata 辞書から DGHTP ヘッダーを構築し、バイト列として返します。
    """
    lines = ["#!DGHTP START"]
    for key, value in metadata.items():
        lines.append(f"#!{key.upper():<12} {value}")
    lines.append("#!DGHTP END")
    header_str = "\n".join(lines) + "\n"  # ヘッダー末尾に改行
    return header_str.encode()

async def send_body(writer: asyncio.StreamWriter,
                    plaintext: bytes,
                    encrypt: bool,
                    compress: bool,
                    password: str = None) -> None:
    """
    ボディデータをチャンクに分割して送信します。
    ・暗号化が有効な場合は送信前に salt+IV を送信し、AES-CFB の encryptor を利用
    ・圧縮が有効な場合は各チャンクごとに zstd 圧縮を適用
    """
    # 初期化処理
    if compress:
        compressor = zstd.ZstdCompressor(level=1)
    else:
        compressor = None

    if encrypt:
        if not password:
            raise ValueError("Password Needed.")
        salt = secrets.token_bytes(SALT_LENGTH)
        iv = secrets.token_bytes(IV_LENGTH)
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        # 送信側として、まず salt と IV を送信
        writer.write(salt + iv)
        await writer.drain()
    else:
        encryptor = None

    # 送信する平文の総長はヘッダーで通知済みのため、こちらは変換処理用
    idx = 0
    total_len = len(plaintext)
    while idx < total_len:
        chunk = plaintext[idx: idx + CHUNK_SIZE]
        idx += CHUNK_SIZE
        # 圧縮処理（任意）
        if compressor:
            chunk = compressor.compress(chunk)
        # 暗号化処理（任意）
        if encryptor:
            chunk = encryptor.update(chunk)
        # チャンクの長さを 8 バイト（big endian）で送信し、その後にデータを送信
        writer.write(len(chunk).to_bytes(8, 'big') + chunk)
        await writer.drain()
    # 暗号化の場合、終了処理の結果があれば送信
    if encryptor:
        final_chunk = encryptor.finalize()
        if final_chunk:
            writer.write(len(final_chunk).to_bytes(8, 'big') + final_chunk)
            await writer.drain()

async def receive_body(reader: asyncio.StreamReader,
                       expected_plain_length: int,
                       encrypt: bool,
                       compress: bool,
                       password: str = None) -> bytes:
    """
    チャンク化されたボディデータを受信し、必要に応じて復号／解凍し平文を再構築します。  
    expected_plain_length: ヘッダーで通知された平文長
    """
    if compress:
        decompressor = zstd.ZstdDecompressor()
    else:
        decompressor = None

    if encrypt:
        if not password:
            raise ValueError("Password Needed.")
        # 受信側では、まず salt と IV を読み込む
        salt_iv = await reader.readexactly(SALT_LENGTH + IV_LENGTH)
        salt = salt_iv[:SALT_LENGTH]
        iv = salt_iv[SALT_LENGTH:]
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
    else:
        decryptor = None

    collected = bytearray()
    # expected_plain_length は復元後のデータ量
    while len(collected) < expected_plain_length:
        # まずチャンク長（8 バイト）を読み込む
        chunk_len_bytes = await reader.readexactly(8)
        chunk_len = int.from_bytes(chunk_len_bytes, 'big')
        # チャンク内容を読み込み
        chunk = await reader.readexactly(chunk_len)
        # 暗号化されている場合は復号
        if decryptor:
            chunk = decryptor.update(chunk)
        # 圧縮が有効なら解凍
        if decompressor:
            chunk = decompressor.decompress(chunk)
        collected.extend(chunk)
    # 暗号化の場合、復号終了処理を実施
    if decryptor:
        final_chunk = decryptor.finalize()
        if final_chunk:
            collected.extend(final_chunk)
    # expected_plain_length を上回っている場合は切り詰める
    return bytes(collected[:expected_plain_length])

##
## DGHTP クライアント実装（リクエスト送信／レスポンス受信）
##
class DGHTPClient:
    def __init__(self, server: str, port: int, method: str, path: str,
                 body: bytes = b"", encrypt: bool = False,
                 compress: bool = False, password: str = None):
        self.server = server
        self.port = port
        self.method = method.upper()
        self.path = path
        self.body = body
        self.encrypt = encrypt
        self.compress = compress
        self.password = password

    async def send_request(self) -> bytes:
        reader, writer = await asyncio.open_connection(self.server, self.port)
        # ヘッダー情報の構築
        metadata = {
            "VERSION": DGHTP_VERSION,
            "METHOD": self.method,
            "PATH": self.path,
            "ENCRYPT": "1" if self.encrypt else "0",
            "COMPRESS": "1" if self.compress else "0",
            "CONTENT-LENGTH": str(len(self.body))
        }
        header = build_dghtp_header(metadata)
        writer.write(header)
        await writer.drain()

        # リクエストボディ送信（ボディがない場合は何も送られない）
        if self.body:
            await send_body(writer, self.body, self.encrypt, self.compress, self.password)

        # レスポンスヘッダー受信
        resp_header = await read_dghtp_header(reader)
        status = resp_header.get("STATUS", "000")
        try:
            resp_length = int(resp_header.get("CONTENT-LENGTH", "0"))
        except ValueError:
            resp_length = 0
        resp_encrypt = bool(int(resp_header.get("ENCRYPT", "0")))
        resp_compress = bool(int(resp_header.get("COMPRESS", "0")))

        # レスポンスボディ受信
        resp_body = await receive_body(reader, resp_length, resp_encrypt, resp_compress, self.password)
        writer.close()
        await writer.wait_closed()

        print(f"[Client] Received response: STATUS={status}, LENGTH={len(resp_body)} bytes")
        return resp_body

##
## DGHTP サーバー実装（シンプルな GET/POST 処理）
##
class DGHTPServer:
    def __init__(self, host: str, port: int, docroot: str,
                 encrypt: bool = False, compress: bool = False,
                 password: str = None,
                 post_enabled: bool = False, get_enabled: bool = True):
        self.host = host
        self.port = port
        self.docroot = docroot  # GET の場合はここからファイルを探す／POST ではアップロード先ディレクトリ
        self.encrypt = encrypt
        self.compress = compress
        self.password = password
        self.post_enabled = post_enabled
        self.get_enabled = get_enabled

    async def start_server(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f"[Server] Listening on {addrs}")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peername = writer.get_extra_info("peername")
        print(f"[Server] Connection from {peername}")
        try:
            req_header = await read_dghtp_header(reader)
        except Exception as e:
            print(f"[Server] Header Receive Error: {e}")
            writer.close()
            await writer.wait_closed()
            return

        method = req_header.get("METHOD", "GET").upper()
        path = req_header.get("PATH", "/")
        try:
            content_length = int(req_header.get("CONTENT-LENGTH", "0"))
        except ValueError:
            content_length = 0
        req_encrypt = bool(int(req_header.get("ENCRYPT", "0")))
        req_compress = bool(int(req_header.get("COMPRESS", "0")))

        # サーバー側の暗号化設定と不一致があるとエラーにする（必須の場合）
        if self.encrypt and not req_encrypt:
            print("[Server] Not Needed Encryption for This Server. Please Remove `--encrypt` Option.")
            writer.close()
            await writer.wait_closed()
            return

        # メソッドごとに許可されているかチェック
        if method == "POST":
            if not self.post_enabled:
                status = "405 Method Not Allowed"
                resp_body = b"POST method not allowed on this server."
                print(f"[Server] POST requested but not enabled.")
            elif content_length > 0:
                # POST の場合、docroot 内にアップロード先ファイルとして保存する例
                body = await receive_body(reader, content_length, req_encrypt, req_compress, self.password)
                upload_path = os.path.join(self.docroot, os.path.basename(path))
                with open(upload_path, 'wb') as f:
                    f.write(body)
                print(f"[Server] POST: Saved Data to {upload_path} ({len(body)} bytes)")
                resp_body = f"POST upload to {upload_path} saved. ({len(body)} bytes)".encode()
                status = "200 OK"
            else:
                status = "400 Bad Request"
                resp_body = b"POST method requires a non-empty body."
        elif method == "GET":
            if not self.get_enabled:
                status = "405 Method Not Allowed"
                resp_body = b"GET method not allowed on this server."
                print(f"[Server] GET requested but not enabled.")
            else:
                file_path = os.path.join(self.docroot, path.lstrip("/"))
                if os.path.isfile(file_path):
                    with open(file_path, 'rb') as f:
                        resp_body = f.read()
                    status = "200 OK"
                    print(f"[Server] GET: Sending {file_path} ({len(resp_body)} bytes)")
                else:
                    status = "404 Not Found"
                    resp_body = b"404 Not Found"
                    print(f"[Server] GET: {file_path} is Not Found.")
        else:
            status = "405 Method Not Allowed"
            resp_body = b"Method not allowed"
            print(f"[Server] Method {method} is Not Supported")

        # レスポンスヘッダー作成
        resp_metadata = {
            "VERSION": DGHTP_VERSION,
            "STATUS": status,
            "ENCRYPT": "1" if self.encrypt else "0",
            "COMPRESS": "1" if self.compress else "0",
            "CONTENT-LENGTH": str(len(resp_body))
        }
        resp_header = build_dghtp_header(resp_metadata)
        writer.write(resp_header)
        await writer.drain()

        # レスポンスボディ送信
        if resp_body:
            await send_body(writer, resp_body, self.encrypt, self.compress, self.password)

        writer.close()
        await writer.wait_closed()
        print(f"[Server] Sent Response to {peername}")

##
## コマンドライン引数のパースとメイン処理
##
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="DGHTP - DiamondGotCat Hypertext Transfer Protocol"
    )
    subparsers = parser.add_subparsers(dest="mode", help="server or client")

    # サーバーモード
    server_parser = subparsers.add_parser("server", help="Server Mode (Share File)")
    server_parser.add_argument("--host", type=str, default="0.0.0.0", help="Host for Bind (Default: 0.0.0.0, use 0.0.0.0 to Connect from Anywhere.)")
    server_parser.add_argument("--port", type=int, default=8443, help="Receive Port (Default: 8443)")
    server_parser.add_argument("docroot", type=str, help="Document Root (Shared Directory)")
    server_parser.add_argument("--encrypt", action="store_true", help="Encryption (Option)")
    server_parser.add_argument("--compress", action="store_true", help="Compress (Option)")
    server_parser.add_argument("--password", type=str, help="Passphase (Need for Encryption)")
    # 新たにPOST/GETの有効/無効を指定する引数を追加
    server_parser.add_argument("--post-enabled", dest="post_enabled", action="store_true", help="Enable POST requests (default: False)")
    server_parser.add_argument("--no-post-enabled", dest="post_enabled", action="store_false", help="Disable POST requests (default: False)")
    server_parser.set_defaults(post_enabled=False)
    server_parser.add_argument("--get-enabled", dest="get_enabled", action="store_true", help="Enable GET requests (default: True)")
    server_parser.add_argument("--no-get-enabled", dest="get_enabled", action="store_false", help="Disable GET requests (default: True)")
    server_parser.set_defaults(get_enabled=True)

    # クライアントモード
    client_parser = subparsers.add_parser("client", help="Client Mode")
    client_parser.add_argument("--server", type=str, required=True, help="Remote IP Address / Domain")
    client_parser.add_argument("--port", type=int, default=8443, help="Remote Port (Default: 8443)")
    client_parser.add_argument("--method", type=str, choices=["GET", "POST"], default="GET", help="Method (Default: GET)")
    client_parser.add_argument("--path", type=str, default="/index.html", help="Request File Path (Default: /index.html)")
    # GET でダウンロード結果を保存する場合の出力先
    client_parser.add_argument("--output", type=str, help="Path for Save Received File (POST)")
    # POST で送信するファイル
    client_parser.add_argument("--file", type=str, help="Path of Send File (POST)")
    client_parser.add_argument("--encrypt", action="store_true", help="Encryption (Option)")
    client_parser.add_argument("--compress", action="store_true", help="Compress (Option)")
    client_parser.add_argument("--password", type=str, help="Passphase (Need for Encryption)")
    return parser.parse_args()

async def main():
    args = parse_arguments()
    if args.mode == "server":
        # パスワードの入力（暗号化有効時）
        password = args.password
        if args.encrypt and not password:
            password = getpass.getpass(prompt="Please enter Passphase: ")
        # docroot が存在するかチェック
        if not os.path.isdir(args.docroot):
            print(f"[ERR] ディレクトリが存在しません: {args.docroot}")
            sys.exit(1)
        server = DGHTPServer(
            host=args.host,
            port=args.port,
            docroot=args.docroot,
            encrypt=args.encrypt,
            compress=args.compress,
            password=password,
            post_enabled=args.post_enabled,
            get_enabled=args.get_enabled
        )
        await server.start_server()

    elif args.mode == "client":
        # パスワードの入力（暗号化有効時）
        password = args.password
        if args.encrypt and not password:
            password = getpass.getpass(prompt="Please enter Passphase: ")
        # リクエストボディの用意
        if args.method.upper() == "POST":
            if not args.file or not os.path.isfile(args.file):
                print(f"[ERR] Not Found File {args.file} for Sending with POST method.")
                sys.exit(1)
            with open(args.file, 'rb') as f:
                body = f.read()
        else:
            body = b""
        client = DGHTPClient(
            server=args.server,
            port=args.port,
            method=args.method,
            path=args.path,
            body=body,
            encrypt=args.encrypt,
            compress=args.compress,
            password=password
        )
        resp_body = await client.send_request()
        # GET の場合、--output が指定されていればファイルに保存、なければ標準出力へ出力
        if args.method.upper() == "GET":
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(resp_body)
                print(f"[Client] Response saved to {args.output}")
            else:
                print("[Client] Response:")
                try:
                    print(resp_body.decode())
                except Exception:
                    print(resp_body)
    else:
        print("Please select Mode(client/server)")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[WARN] PROCESS EXITED: KeyboardInterrupt")
