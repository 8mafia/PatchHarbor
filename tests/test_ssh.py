"""A disposable loopback SSH fixture. It never executes a shell command."""
import socket
import threading
import time

import paramiko

import engine


def test_real_ssh_handshake_password_fallback_sudo_stdin_and_redaction():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    listener.settimeout(.2)
    key = paramiko.RSAKey.generate(2048)
    stopped = threading.Event()
    requests, passwords, workers = [], [], []

    class SSHServer(paramiko.ServerInterface):
        def __init__(self):
            self.ready = threading.Event()
            self.command = None
        def get_allowed_auths(self, username): return "password"
        def check_auth_password(self, username, password):
            passwords.append(password)
            return paramiko.AUTH_SUCCESSFUL if password == "fixture-correct" else paramiko.AUTH_FAILED
        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_exec_request(self, channel, command):
            self.command = command.decode()
            self.ready.set()
            return True

    def serve(sock):
        transport = paramiko.Transport(sock)
        try:
            transport.add_server_key(key)
            server = SSHServer()
            transport.start_server(server=server)
            for _ in range(2):
                channel = transport.accept(4)
                if channel is None or not server.ready.wait(4): return
                server.ready.clear()
                channel.settimeout(4)
                if 'id -u' in server.command:
                    channel.sendall(b"1000\n")
                else:
                    incoming = b""
                    while not incoming.endswith(b"\n"):
                        data = channel.recv(4096)
                        if not data: break
                        incoming += data
                    requests.append((server.command, incoming.decode()))
                    channel.sendall(b"fixture-correct\nPHP 8.3.36\n")
                channel.send_exit_status(0)
                time.sleep(.1)
                channel.close()
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()

    def accept_loop():
        while not stopped.is_set():
            try: sock, _ = listener.accept()
            except socket.timeout: continue
            except OSError: break
            worker = threading.Thread(target=serve, args=(sock,), daemon=True)
            workers.append(worker)
            worker.start()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    server = {"host": "127.0.0.1", "port": listener.getsockname()[1], "username": "fixture", "trusted": {"fingerprint": engine.fingerprint(key)}}
    credentials = {"passwords": ["fixture-wrong", "fixture-correct"], "sudo_password": "fixture-sudo-password"}
    try:
        with engine.Remote(server, credentials) as remote:
            result = remote.run("printf 'fixture'", privileged=True, timeout=5)
        assert result.code == 0 and "PHP 8.3.36" in result.output
        assert "fixture-correct" not in result.output
        assert requests[0][0].startswith("sudo -S -p '' -- sh -c")
        assert "fixture-sudo-password" not in requests[0][0]
        assert requests[0][1] == "fixture-correct\n"
        assert passwords == ["fixture-wrong", "fixture-correct"]
    finally:
        stopped.set()
        listener.close()
        thread.join(1)
        for worker in workers: worker.join(5)
