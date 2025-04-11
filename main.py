import asyncio
import os
import argparse
import tempfile
import shutil
import time

from dgctp import lib, calculate_sha256

PORT = 4321  # デフォルト受信ポート
RECEIVE_DIR = tempfile.mkdtemp(prefix="dgctp_recv_")

class DGCTPInteractiveNode:
    def __init__(self, nofile=False):
        self.nofile = nofile
        self.responded_hashes = set()

    async def handle_received_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()

            print(f"[RECV] From peer: '{content}'")

            # 要求されたファイルを返す（または None）
            if self.nofile:
                reply = "None"
            else:
                if os.path.isfile(content):
                    with open(content, 'r', encoding='utf-8', errors='ignore') as f:
                        reply = f.read()
                else:
                    reply = "[ERR] File not found"

            # 応答ファイル作成
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmpf:
                tmpf.write(reply)
                reply_path = tmpf.name

            await lib(
                mode='send',
                target='127.0.0.1',
                port=PORT,
                file_path=reply_path,
                compress=False,
                encrypt=False
            )
            print("[SEND] Sent reply.")
            os.remove(reply_path)

        except Exception as e:
            print(f"[ERR ] while responding: {e}")

    async def receive_loop(self):
        while True:
            try:
                await lib(
                    mode='receive',
                    port=PORT,
                    save_dir=RECEIVE_DIR,
                    encrypt=False
                )

                # 最新ファイルを処理
                files = sorted(
                    (os.path.join(RECEIVE_DIR, f) for f in os.listdir(RECEIVE_DIR)),
                    key=os.path.getctime
                )
                if files:
                    latest_file = files[-1]
                    await self.handle_received_file(latest_file)
                    os.remove(latest_file)
            except Exception as e:
                print(f"[ERR ] Receive loop: {e}")
                await asyncio.sleep(1)

    async def send_once(self, target_ip, target_port, path_str):
        # 送信用に一時ファイル作成
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmpf:
            tmpf.write(path_str)
            send_path = tmpf.name

        await lib(
            mode='send',
            target=target_ip,
            port=target_port,
            file_path=send_path,
            compress=False,
            encrypt=False
        )
        os.remove(send_path)

        # 応答を待って受信
        await lib(
            mode='receive',
            port=PORT,
            save_dir=RECEIVE_DIR,
            encrypt=False
        )
        files = sorted(
            (os.path.join(RECEIVE_DIR, f) for f in os.listdir(RECEIVE_DIR)),
            key=os.path.getctime
        )
        if files:
            reply_file = files[-1]
            with open(reply_file, 'r', encoding='utf-8', errors='ignore') as f:
                reply_content = f.read().strip()
            os.remove(reply_file)
            print(f"[REPLY] <<< {reply_content}")

    async def input_loop(self):
        print(f"[INFO] Enter commands like: 127.0.0.1[:PORT]/path/to/request.txt")
        while True:
            try:
                user_input = input(">>> ").strip()
                if not user_input or '/' not in user_input:
                    print("[ERR] Format must be IP[:PORT]/file_path")
                    continue

                address, filepath = user_input.split('/', 1)

                if ':' in address:
                    ip, port_str = address.split(':')
                    port = int(port_str)
                else:
                    ip = address
                    port = PORT  # デフォルトポート

                await self.send_once(ip, port, filepath)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[ERR] Input error: {e}")

    def cleanup(self):
        shutil.rmtree(RECEIVE_DIR)

async def main():
    parser = argparse.ArgumentParser(description="DGCTP Interactive Node")
    parser.add_argument('--nofile', action='store_true', help='Respond with None instead of file content')
    args = parser.parse_args()

    node = DGCTPInteractiveNode(nofile=args.nofile)

    try:
        # 並列タスク起動：受信 + 入力ループ
        await asyncio.gather(
            node.receive_loop(),
            node.input_loop()
        )
    except KeyboardInterrupt:
        print("\n[EXIT] Interrupted by user.")
        node.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
