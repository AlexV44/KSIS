import socket
import threading
import re
import sys
from urllib.parse import urlparse

# ---------- Чёрный список ----------
BLACKLIST_FILE = "blacklist.txt"

def load_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        return []

BLACKLIST = load_blacklist()

def is_blocked(host, full_url):
    full_url_lower = full_url.lower()
    host_lower = host.lower()
    for blocked in BLACKLIST:
        if blocked in host_lower or blocked in full_url_lower:
            return True
    return False

def build_forbidden_response():
    body = b"""<html>
<head><title>403 Forbidden</title></head>
<body>
<h1>Access Denied</h1>
<p>The resource you requested is blacklisted by the proxy server.</p>
</body>
</html>"""
    response = b"HTTP/1.1 403 Forbidden\r\n"
    response += b"Content-Type: text/html\r\n"
    response += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    response += b"Connection: close\r\n\r\n"
    response += body
    return response

def build_method_not_allowed():
    body = "<html><body><h1>405 Method Not Allowed</h1><p>This proxy only supports HTTP (not HTTPS).</p></body></html>"
    response = f"HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
    return response.encode()

def handle_client(client_sock, client_addr):
    client_sock.settimeout(10.0)

    try:
        # Читаем первую строку запроса
        request_line = b""
        while b"\r\n" not in request_line:
            chunk = client_sock.recv(1)
            if not chunk:
                return
            request_line += chunk
        request_line = request_line.decode().strip()

        # Читаем заголовки
        headers = b""
        while b"\r\n\r\n" not in headers:
            chunk = client_sock.recv(1024)
            if not chunk:
                return
            headers += chunk

        full_request = (request_line + "\r\n" + headers.decode()).encode()
        parts = request_line.split()
        if len(parts) < 2:
            return
        method = parts[0].upper()
        url_or_host = parts[1]

        # ---------- CONNECT (HTTPS) – просто закрываем без вывода ----------
        if method == "CONNECT":
            client_sock.sendall(build_method_not_allowed())
            client_sock.close()
            return

        # ---------- Парсинг URL ----------
        if url_or_host.startswith("http://"):
            parsed = urlparse(url_or_host)
            host = parsed.hostname
            port = parsed.port if parsed.port else 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            full_url = url_or_host  # сохраняем полный URL для вывода
        else:
            # Относительный путь – берём Host из заголовка
            host_match = re.search(rb"Host: (.*?)\r\n", headers, re.IGNORECASE)
            if not host_match:
                return
            host_port = host_match.group(1).decode()
            if ":" in host_port:
                host, port = host_port.split(":")
                port = int(port)
            else:
                host = host_port
                port = 80
            path = url_or_host
            full_url = f"http://{host}:{port}{path}"  # восстанавливаем полный URL

        # ---------- Чёрный список ----------
        if is_blocked(host, full_url):
            client_sock.sendall(build_forbidden_response())
            client_sock.close()
            return

        # ---------- Подключение к целевому серверу ----------
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.settimeout(10.0)
        try:
            target_sock.connect((host, port))
        except Exception:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client_sock.close()
            return

        # ---------- Модификация запроса ----------
        modified_request = full_request.replace(url_or_host.encode(), path.encode(), 1)
        modified_request = re.sub(rb"Proxy-Connection:.*\r\n", b"", modified_request, flags=re.IGNORECASE)
        if re.search(rb"Host:.*\r\n", modified_request, re.IGNORECASE):
            modified_request = re.sub(rb"Host:.*\r\n", f"Host: {host}\r\n".encode(), modified_request, flags=re.IGNORECASE)
        else:
            first_line_end = modified_request.find(b"\r\n") + 2
            modified_request = modified_request[:first_line_end] + f"Host: {host}\r\n".encode() + modified_request[first_line_end:]

        target_sock.sendall(modified_request)

        # ---------- Чтение ответа сервера ----------
        response_header = b""
        while b"\r\n\r\n" not in response_header:
            chunk = target_sock.recv(1024)
            if not chunk:
                break
            response_header += chunk

        # Извлекаем код и текстовое пояснение из первой строки
        status_code = "???"
        status_text = ""
        if response_header:
            first_line = response_header.split(b"\r\n")[0].decode(errors='ignore')
            if " " in first_line:
                parts_status = first_line.split(" ", 2)
                if len(parts_status) >= 2:
                    status_code = parts_status[1]
                    if len(parts_status) >= 3:
                        status_text = parts_status[2]
        # Вывод в нужном формате (только это сообщение будет в консоли)
        print(f"{full_url} - {status_code} {status_text}")

        # Пересылаем заголовки клиенту
        try:
            client_sock.sendall(response_header)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            target_sock.close()
            return

        # Пересылаем тело
        while True:
            try:
                data = target_sock.recv(8192)
                if not data:
                    break
                client_sock.sendall(data)
            except (socket.timeout, BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                break

    except Exception:
        # Все ошибки игнорируем, чтобы не засорять вывод
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass

def start_proxy(host="0.0.0.0", port=8080):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(100)
    # Единственное сообщение при старте (можно убрать, но оставим для информации)
    print(f"[+] Proxy started on {host}:{port}", file=sys.stderr)  # в stderr, не в основной вывод
    try:
        while True:
            client_sock, client_addr = server_sock.accept()
            thread = threading.Thread(target=handle_client, args=(client_sock, client_addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        server_sock.close()
        sys.exit(0)

if __name__ == "__main__":
    start_proxy()