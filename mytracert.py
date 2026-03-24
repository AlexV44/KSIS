#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
traceroute.py - утилита трассировки маршрута для Windows (аналог tracert)
Запуск требует прав администратора (для создания сырого ICMP-сокета).
"""

import socket
import struct
import sys
import time
import argparse
import threading
import os
import platform

# Константы ICMP
ICMP_ECHO_REQUEST = 8   # Запрос Ping
ICMP_ECHO_REPLY = 0     # Ответ Ping
ICMP_TIME_EXCEEDED = 11 # Превышен TTL (промежуточный маршрутизатор)
ICMP_DEST_UNREACH = 3   # Пункт назначения недоступен


def checksum(packet):
    """
    Вычисление контрольной суммы ICMP-пакета (RFC 1071).
    """
    if len(packet) % 2 == 1:
        packet += b'\0'
    s = sum(struct.unpack('!%dH' % (len(packet) // 2), packet))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def create_icmp_packet(identifier, sequence, payload=b''):
    """
    Формирует ICMP Echo Request пакет.
    identifier и sequence должны быть 2-байтовыми целыми.
    """
    # Заголовок ICMP (8 байт): тип, код, контрольная сумма, идентификатор, номер последовательности
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, identifier, sequence)
    packet = header + payload
    # Вычисляем контрольную сумму и вставляем в заголовок
    ck = checksum(packet)
    packet = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, ck, identifier, sequence) + payload
    return packet


def parse_icmp_reply(data):
    """
    Извлекает из IP-пакета ICMP-сообщение и возвращает (тип, код, исходный IP).
    Для пакетов Time Exceeded или Destination Unreachable также пытается
    извлечь исходный идентификатор и номер последовательности из вложенного пакета.
    """
    # IP-заголовок минимум 20 байт
    ip_header = data[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    proto = iph[6]  # протокол (должен быть 1 для ICMP)
    src_ip = socket.inet_ntoa(iph[8])  # IP отправителя ICMP-сообщения

    # ICMP-заголовок начинается после IP-заголовка
    icmp_start = (iph[0] & 0x0F) * 4  # длина IP-заголовка в байтах
    icmp_header = data[icmp_start:icmp_start+8]
    icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_header)

    # Для сообщений об ошибке (тип 11 или 3) внутри есть исходный IP-пакет + 8 байт исходного ICMP
    orig_id = None
    orig_seq = None
    if icmp_type in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACH):
        if len(data) >= icmp_start + 8 + 28:  # минимум: ICMP ошибки (8) + IP (20) + 8 байт ICMP
            orig_ip_header = data[icmp_start+8:icmp_start+8+20]
            orig_icmp = data[icmp_start+8+20:icmp_start+8+20+8]
            if len(orig_icmp) >= 8:
                _, _, _, orig_id, orig_seq = struct.unpack('!BBHHH', orig_icmp)

    return icmp_type, icmp_code, src_ip, orig_id, orig_seq


class Traceroute:
    def __init__(self, target, max_hops=30, timeout=2, resolve=True, port=0):
        self.target = target
        self.max_hops = max_hops
        self.timeout = timeout
        self.resolve = resolve
        self.dest_ip = None
        self.pid = os.getpid() & 0xFFFF  # идентификатор процесса для ICMP ID
        self.seq = 0
        self.sock = None

    def resolve_target(self):
        """Разрешает имя хоста в IP-адрес."""
        try:
            self.dest_ip = socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            return False

    def create_socket(self):
        """Создаёт сырой сокет для ICMP."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.sock.settimeout(self.timeout)
            # Устанавливаем TTL для исходящих пакетов (будет меняться для каждого хопа)
            return True
        except PermissionError:
            print("Ошибка: Требуются права администратора для создания сырого сокета.")
            return False
        except Exception as e:
            print(f"Ошибка создания сокета: {e}")
            return False

    def send_probe(self, ttl):
        """Отправляет один ICMP Echo Request с заданным TTL."""
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        # Уникальные идентификатор и номер последовательности для этого запроса
        identifier = self.pid
        sequence = (ttl << 8) | self.seq  # комбинируем TTL и номер пробы
        # Заполняем данные пакета (можно добавить временную метку, но мы засекаем время отдельно)
        payload = b'abcdefghijklmnopqrstuvwabcdefghi'  # 32 байта данных
        packet = create_icmp_packet(identifier, sequence, payload)
        # Засекаем время отправки
        send_time = time.perf_counter()
        try:
            self.sock.sendto(packet, (self.dest_ip, 0))
        except Exception as e:
            print(f"Ошибка отправки: {e}")
            return None
        return send_time

    def receive_probe(self, expected_seq):
        """Ожидает ответ и возвращает (ip, rtt) или (None, None) при таймауте."""
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)  # макс размер пакета
                recv_time = time.perf_counter()
                # Разбираем полученный пакет
                icmp_type, icmp_code, src_ip, orig_id, orig_seq = parse_icmp_reply(data)

                # Проверяем, что это ответ на наш запрос
                # Для Echo Reply: ID и Seq должны совпадать с отправленными
                if icmp_type == ICMP_ECHO_REPLY and orig_id == self.pid and orig_seq == expected_seq:
                    return src_ip, recv_time
                # Для Time Exceeded или Unreachable: проверяем вложенные ID и Seq
                elif icmp_type in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACH) and orig_id == self.pid and orig_seq == expected_seq:
                    return src_ip, recv_time
                # Игнорируем чужие пакеты
                else:
                    continue
            except socket.timeout:
                return None, None
            except Exception as e:
                print(f"Ошибка приёма: {e}")
                return None, None

    def lookup_hostname(self, ip):
        """DNS PTR запрос для получения имени хоста."""
        if not self.resolve:
            return ip
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return f"{hostname} [{ip}]"
        except socket.herror:
            return ip

    def run(self):
        """Основной цикл трассировки."""
        if not self.resolve_target():
            print(f"Не удалось разрешить {self.target}")
            sys.exit(1)

        if not self.create_socket():
            sys.exit(1)

        print(f"Трассировка маршрута к {self.target} [{self.dest_ip}]")
        print(f"с максимальным числом прыжков {self.max_hops}:\n")

        reached = False
        for ttl in range(1, self.max_hops + 1):
            # Вывод строки номера хопа
            sys.stdout.write(f"{ttl:3}  ")
            sys.stdout.flush()

            responses = []  # список IP для этого хопа (обычно один и тот же)
            rtts = []

            # Делаем три попытки
            for attempt in range(3):
                self.seq = attempt  # сохраняем номер попытки в поле seq
                expected_seq = (ttl << 8) | attempt
                send_time = self.send_probe(ttl)
                if send_time is None:
                    rtts.append(None)
                    continue

                src_ip, recv_time = self.receive_probe(expected_seq)
                if src_ip is None:
                    rtts.append(None)
                else:
                    rtt = (recv_time - send_time) * 1000  # в миллисекундах
                    rtts.append(rtt)
                    responses.append(src_ip)

                # Небольшая пауза между попытками, чтобы не забить сеть
                time.sleep(0.1)

            # Формируем строку с временами
            for rtt in rtts:
                if rtt is None:
                    sys.stdout.write("   *   ")
                else:
                    sys.stdout.write(f"{rtt:4.0f} ms ")

            # Определяем уникальный IP для этого хопа (если есть ответы)
            if responses:
                # Берём последний ответ (обычно все одинаковые)
                hop_ip = responses[-1]
                hop_name = self.lookup_hostname(hop_ip)
                sys.stdout.write(f" {hop_name}")
                # Проверяем, достигли ли цели
                if hop_ip == self.dest_ip:
                    reached = True
            else:
                sys.stdout.write(" Request timed out.")

            sys.stdout.write("\n")
            sys.stdout.flush()

            if reached:
                break

        print("\nТрассировка завершена.")


def is_admin():
    """Проверка прав администратора на Windows."""
    if platform.system() == 'Windows':
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        # На Unix-подобных системах обычно требуется root для сырых сокетов
        return os.geteuid() == 0


def main():
    parser = argparse.ArgumentParser(description="Аналог tracert для Windows на Python")
    parser.add_argument("host", help="Целевой хост или IP-адрес")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="Максимальное число прыжков (по умолчанию 30)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Таймаут ожидания ответа в секундах (по умолчанию 2)")
    parser.add_argument("-n", "--no-dns", action="store_true", help="Не выполнять DNS-запросы имён промежуточных узлов")
    args = parser.parse_args()

    if not is_admin():
        print("Внимание: для работы необходимы права администратора.")
        print("Запустите программу от имени администратора.")
        if platform.system() == 'Windows':
            print("Нажмите правой кнопкой на командной строке -> 'Запуск от имени администратора'.")
        sys.exit(1)

    tracer = Traceroute(
        target=args.host,
        max_hops=args.max_hops,
        timeout=args.timeout,
        resolve=not args.no_dns
    )
    try:
        tracer.run()
    except KeyboardInterrupt:
        print("\nПрерывание пользователя.")
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    main()