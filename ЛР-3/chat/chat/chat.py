import socket
import struct
import threading
import sys
import json
from datetime import datetime
from enum import Enum, auto

# ---------- Константы ----------
DEFAULT_TCP_PORT = 9000
DEFAULT_UDP_PORT = 8888
# Исправлено: ограниченное широковещание для подсети 127.0.0.0/8
BROADCAST_IP = '127.255.255.255'

# ---------- Типы сообщений ----------
class MessageType(Enum):
    CHAT_MESSAGE = auto()
    NAME_TRANSFER = auto()
    PEER_CONNECTED = auto()
    PEER_DISCONNECTED = auto()
    HISTORY_REQUEST = auto()
    HISTORY_RESPONSE = auto()

# ---------- Сообщение ----------
class Message:
    def __init__(self, msg_type: MessageType, content: str,
                 sender_name: str, sender_ip: str, sender_tcp_port: int,
                 timestamp: datetime = None):
        self.type = msg_type
        self.content = content
        self.sender_name = sender_name
        self.sender_ip = sender_ip
        self.sender_tcp_port = sender_tcp_port
        self.timestamp = timestamp or datetime.now()

    def get_formatted_message(self):
        time_str = self.timestamp.strftime("%H:%M:%S")
        t = self.type
        if t == MessageType.CHAT_MESSAGE:
            return f"[{time_str}] {self.sender_name} ({self.sender_ip}): {self.content}"
        elif t == MessageType.PEER_CONNECTED:
            return f"[{time_str}] +++ {self.sender_name} ({self.sender_ip}) подключился"
        elif t == MessageType.PEER_DISCONNECTED:
            return f"[{time_str}] --- {self.sender_name} ({self.sender_ip}) отключился"
        elif t == MessageType.HISTORY_REQUEST:
            return f"[{time_str}] [История запрошена у {self.sender_name} ({self.sender_ip})]"
        elif t == MessageType.HISTORY_RESPONSE:
            return f"[{time_str}] [История получена от {self.sender_name} ({self.sender_ip})]"
        else:
            return f"[{time_str}] {self.content}"

    def serialize(self):
        body = json.dumps({
            'type': self.type.value,
            'content': self.content,
            'sender_name': self.sender_name,
            'sender_ip': self.sender_ip,
            'sender_tcp_port': self.sender_tcp_port,
            'timestamp': self.timestamp.isoformat()
        }).encode('utf-8')
        header = struct.pack('!B I', self.type.value, len(body))
        return header + body

    @staticmethod
    def deserialize(data: bytes):
        if len(data) < 5:
            raise ValueError("Слишком короткое сообщение")
        msg_type_val, body_len = struct.unpack('!B I', data[:5])
        body = json.loads(data[5:5+body_len].decode('utf-8'))
        msg_type = MessageType(body['type'])
        timestamp = datetime.fromisoformat(body['timestamp'])
        return Message(msg_type, body['content'], body['sender_name'],
                       body['sender_ip'], body['sender_tcp_port'], timestamp)

# ---------- История ----------
class HistoryManager:
    def __init__(self):
        self._history = []
        self._lock = threading.Lock()

    def add(self, msg: Message):
        with self._lock:
            self._history.append(msg)

    def get_all(self):
        with self._lock:
            return list(self._history)

# ---------- PeerInfo ----------
class PeerInfo:
    def __init__(self, name: str, ip: str, port: int):
        self.name = name
        self.ip = ip
        self.port = port
        self.socket = None
        self.send_lock = threading.Lock()

    def get_key(self):
        return f"{self.ip}:{self.port}"

    def send(self, msg: Message):
        data = msg.serialize()
        with self.send_lock:
            try:
                self.socket.sendall(data)
            except Exception:
                pass  # обрабатывается в PeerConnectionHandler

# ---------- Обработчик TCP-соединения ----------
class PeerConnectionHandler:
    def __init__(self, node, sock: socket.socket, peer: PeerInfo):
        self.node = node
        self.sock = sock
        self.peer = peer

    def run(self):
        try:
            while True:
                header = self._recv_exact(5)
                if not header:
                    break
                msg_type_val, body_len = struct.unpack('!B I', header)
                body = self._recv_exact(body_len)
                if not body:
                    break
                msg = Message.deserialize(header + body)

                if msg.type == MessageType.NAME_TRANSFER:
                    self.node.on_peer_identified(self.peer, msg)
                elif msg.type == MessageType.CHAT_MESSAGE:
                    self.node.add_msg(msg)
                elif msg.type == MessageType.HISTORY_REQUEST:
                    self.node.send_history(self.peer)
                elif msg.type == MessageType.HISTORY_RESPONSE:
                    self.node.receive_history(msg.content, msg.sender_name, msg.sender_ip)
        except Exception:
            pass
        finally:
            self.node.handle_disconnect(self.peer)

    def _recv_exact(self, n: int) -> bytes:
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return b''
            data += chunk
        return data

# ---------- TCP-сервер ----------
class TcpServer:
    def __init__(self, node, ip: str, port: int):
        self.node = node
        self.ip = ip
        self.port = port

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ss:
            ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ss.bind((self.ip, self.port))
            ss.listen(10)
            print(f"[TCP сервер] слушает {self.ip}:{self.port}")
            while True:
                try:
                    client, addr = ss.accept()
                    print(f"[TCP] входящее соединение от {addr}")
                    peer = PeerInfo("Unknown", addr[0], addr[1])
                    peer.socket = client
                    threading.Thread(
                        target=PeerConnectionHandler(self.node, client, peer).run,
                        daemon=True
                    ).start()
                except Exception as e:
                    print(f"[TCP сервер] ошибка: {e}")

# ---------- UDP-слушатель ----------
class UdpBroadcastListener:
    def __init__(self, node, port: int):
        self.node = node
        self.port = port

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ds:
            ds.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ds.bind((self.node.local_ip, self.port))
            print(f"[UDP слушатель] слушает {self.node.local_ip}:{self.port}")
            while True:
                try:
                    data, addr = ds.recvfrom(1024)
                    decoded = data.decode('utf-8')
                    parts = decoded.split(":")
                    if len(parts) == 3:
                        name, ip, tcp_port_str = parts
                        tcp_port = int(tcp_port_str)
                        # Игнорируем самого себя
                        if ip == self.node.local_ip and tcp_port == self.node.tcp_port:
                            continue
                        print(f"[UDP] обнаружен {name} ({ip}:{tcp_port})")
                        self.node.connect_to_peer(ip, tcp_port, name)
                except Exception as e:
                    print(f"[UDP слушатель] ошибка: {e}")

# ---------- Главный узел ----------
class PeerNode:
    def __init__(self, name: str, local_ip: str, udp_port: int, tcp_port: int):
        self.name = name
        self.local_ip = local_ip
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.peers = {}
        self.history_manager = HistoryManager()
        self.listener = None
        self.history_requested = False
        self._lock = threading.Lock()

    def set_listener(self, listener):
        self.listener = listener

    def start(self):
        threading.Thread(target=TcpServer(self, self.local_ip, self.tcp_port).run, daemon=True).start()
        threading.Thread(target=UdpBroadcastListener(self, self.udp_port).run, daemon=True).start()
        self._send_discovery()
        print(f"Узел {self.name} запущен ({self.local_ip}:{self.tcp_port})")

    def _send_discovery(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ds:
                ds.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                data = f"{self.name}:{self.local_ip}:{self.tcp_port}".encode('utf-8')
                ds.sendto(data, (BROADCAST_IP, self.udp_port))
                print(f"[UDP] отправлено широковещание на {BROADCAST_IP}:{self.udp_port}")
        except Exception as e:
            print(f"[UDP] ошибка отправки широковещания: {e}")

    def connect_to_peer(self, ip: str, port: int, peer_name: str):
        key = f"{ip}:{port}"
        with self._lock:
            if key in self.peers:
                return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.settimeout(None)
            peer = PeerInfo(peer_name, ip, port)
            peer.socket = sock

            with self._lock:
                if key in self.peers:
                    sock.close()
                    return
                self.peers[key] = peer

            threading.Thread(
                target=PeerConnectionHandler(self, sock, peer).run,
                daemon=True
            ).start()

            self._send_message(peer, Message(
                MessageType.NAME_TRANSFER, self.name, self.name, self.local_ip, self.tcp_port
            ))

            self._on_peer_connected(peer)
        except Exception as e:
            print(f"[TCP] ошибка подключения к {peer_name} ({ip}:{port}): {e}")

    def on_peer_identified(self, peer: PeerInfo, msg: Message):
        peer.name = msg.sender_name
        peer.port = msg.sender_tcp_port
        with self._lock:
            self.peers[peer.get_key()] = peer
        if not self.history_requested:
            self.history_requested = True
            self._send_message(peer, Message(
                MessageType.HISTORY_REQUEST, "", self.name, self.local_ip, self.tcp_port
            ))

    def send_chat_message(self, text: str):
        msg = Message(MessageType.CHAT_MESSAGE, text, self.name, self.local_ip, self.tcp_port)
        self.history_manager.add(msg)
        if self.listener:
            self.listener.on_message(msg.get_formatted_message())
        with self._lock:
            peers = list(self.peers.values())
        for peer in peers:
            self._send_message(peer, msg)

    def _send_message(self, peer: PeerInfo, msg: Message):
        try:
            peer.send(msg)
        except Exception as e:
            print(f"[TCP] ошибка отправки сообщения: {e}")

    def _on_peer_connected(self, peer: PeerInfo):
        msg = Message(MessageType.PEER_CONNECTED, "", peer.name, peer.ip, peer.port)
        self.history_manager.add(msg)
        if self.listener:
            self.listener.on_message(msg.get_formatted_message())

    def handle_disconnect(self, peer: PeerInfo):
        with self._lock:
            removed = self.peers.pop(peer.get_key(), None)
        if removed:
            msg = Message(MessageType.PEER_DISCONNECTED, "", peer.name, peer.ip, peer.port)
            self.history_manager.add(msg)
            if self.listener:
                self.listener.on_message(msg.get_formatted_message())

    def add_msg(self, msg: Message):
        self.history_manager.add(msg)
        if self.listener:
            self.listener.on_message(msg.get_formatted_message())

    def send_history(self, peer: PeerInfo):
        all_msgs = self.history_manager.get_all()
        history_json = json.dumps([{
            'type': m.type.value,
            'content': m.content,
            'sender_name': m.sender_name,
            'sender_ip': m.sender_ip,
            'sender_tcp_port': m.sender_tcp_port,
            'timestamp': m.timestamp.isoformat()
        } for m in all_msgs])
        msg = Message(MessageType.HISTORY_RESPONSE, history_json,
                      self.name, self.local_ip, self.tcp_port)
        self._send_message(peer, msg)

    def receive_history(self, history_json: str, sender_name: str, sender_ip: str):
        try:
            records = json.loads(history_json)
            for rec in records:
                m = Message(
                    MessageType(rec['type']),
                    rec['content'],
                    rec['sender_name'],
                    rec['sender_ip'],
                    rec['sender_tcp_port'],
                    datetime.fromisoformat(rec['timestamp'])
                )
                self.history_manager.add(m)
                if self.listener:
                    self.listener.on_message(m.get_formatted_message())
            notify = Message(MessageType.HISTORY_RESPONSE, "",
                             sender_name, sender_ip, 0)
            if self.listener:
                self.listener.on_message(notify.get_formatted_message())
        except Exception as e:
            print(f"[История] ошибка получения: {e}")

# ---------- Консольный интерфейс ----------
class ConsoleUI:
    def __init__(self, node: PeerNode):
        self.node = node
        node.set_listener(self)

    def start(self):
        print("\nЧат запущен. Вводите сообщения, /exit для выхода.")
        try:
            while True:
                line = input("> ")
                if line.strip().lower() in ("/exit", "/quit"):
                    sys.exit(0)
                if line.strip():
                    self.node.send_chat_message(line.strip())
        except KeyboardInterrupt:
            sys.exit(0)

    def on_message(self, msg: str):
        print(msg)

# ---------- Главная функция ----------
def main():
    args = sys.argv[1:]
    name = "User"
    ip = "127.0.0.1"
    tcp_port = DEFAULT_TCP_PORT
    udp_port = DEFAULT_UDP_PORT

    for arg in args:
        if arg.startswith("--name="):
            name = arg[7:]
        elif arg.startswith("--ip="):
            ip = arg[5:]
        elif arg.startswith("--tcp-port="):
            tcp_port = int(arg[11:])
        elif arg.startswith("--udp-port="):
            udp_port = int(arg[11:])

    # Проверка, что TCP-порт свободен
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ss:
            ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ss.bind((ip, tcp_port))
    except OSError:
        print(f"Ошибка: адрес {ip}:{tcp_port} уже занят. Укажите другой порт.")
        sys.exit(1)

    print(f"\nЗапуск узла: {name} ({ip}) TCP:{tcp_port} UDP:{udp_port}")
    node = PeerNode(name, ip, udp_port, tcp_port)
    ui = ConsoleUI(node)
    node.start()
    ui.start()

if __name__ == "__main__":
    main()