import asyncio
import os
import argparse
import tempfile
import shutil

from dgctp import FileReceiver, lib

PORT = 4321  # デフォルトポート
RECEIVE_DIR = tempfile.mkdtemp(prefix="dgctp_recv_")

class DGCTPInteractiveNode:
    def __init__(self, nofile=False):
        self.nofile = nofile
        self.responded_hashes = set()

    async def handle_received_file(self, file_path, sender_ip):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
            print(f"[RECV] From {sender_ip}: '{content}'")

            if self.nofile:
                reply = "None"
            else:
                if os.path.isfile(content):
                    with open(content, 'r', encoding='utf-8', errors='ignore') as f:
                        reply = f.read()
                else:
                    reply = "[ERR] File not found"

            # 応答ファイルの作成と送信
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmpf:
                tmpf.write(reply)
                reply_path = tmpf.name

            await lib(
                mode='send',
                target=sender_ip,
                port=PORT,
                file_path=reply_path,
                compress=False,
                encrypt=False
            )
            print("[SEND] Sent reply to", sender_ip)
            os.remove(reply_path)

        except Exception as e:
            print(f"[ERR ] while responding: {e}")

    async def on_file_received(self, file_path, sender_ip):
        await self.handle_received_file(file_path, sender_ip)
        os.remove(file_path)

    async def receive_loop(self):
        receiver = FileReceiver(
            port=PORT,
            save_dir=RECEIVE_DIR,
            encrypt=False,
            on_receive=self.on_file_received
        )
        # 非同期タスクとして起動
        asyncio.create_task(receiver.start_server())

    async def send_once(self, target_ip, target_port, path_str):
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

        latest_file, sender_ip = await lib(
            mode='receive',
            port=PORT,
            save_dir=RECEIVE_DIR,
            encrypt=False
        )
        with open(latest_file, 'r', encoding='utf-8', errors='ignore') as f:
            reply_content = f.read().strip()
        os.remove(latest_file)
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
                    port = PORT

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
        await asyncio.gather(
            node.receive_loop(),
            node.input_loop()
        )
    except KeyboardInterrupt:
        print("\n[EXIT] Interrupted by user.")
        node.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
