#!/usr/bin/env python3
"""A caBLE v2 (hybrid) tunnel server, Python standard library only.

The phone and the browser cannot reach each other directly, so both open a
WebSocket to a tunnel server, which pairs them and passes messages back and
forth. Everything it passes is end-to-end encrypted (Noise) between phone and
browser: the server cannot read or change sign-ins, it only sees that a
connection happened.

    phone:   wss://<host>/cable/new/<tunnel id, 32 hex>
             -> 101, header X-Cable-Routing-Id: <3 bytes, 6 hex>
    browser: wss://<host>/cable/connect/<routing id>/<tunnel id>
             -> paired with the phone that is waiting with that routing id
                and tunnel id; from then on every message is forwarded

Both sides must ask for the WebSocket subprotocol "fido.cable".
/cable/contact/... (linked phones) is answered with 410 Gone: current Chrome
no longer links phones from a QR code.

Run it behind a reverse proxy that provides TLS (e.g. Caddy), or give it a
certificate with --tls-cert/--tls-key. See README.md.
"""

import argparse
import asyncio
import base64
import hashlib
import logging
import re
import secrets
import ssl
import struct
import sys
import time

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SUBPROTOCOL = "fido.cable"
MAX_MESSAGE = 1 << 20        # bytes; caBLE messages are a few KiB at most
MAX_QUEUED = 64              # messages buffered from one side before the other arrives
MAX_HEADER = 8192            # bytes of HTTP request header
HANDSHAKE_TIMEOUT = 10       # seconds to send the HTTP upgrade request
WAIT_TIMEOUT = 300           # seconds a phone may wait for its browser
TUNNEL_LIFETIME = 600        # seconds a paired tunnel may stay open
MAX_WAITING = 1000           # phones waiting at the same time

NEW = re.compile(r"^/cable/new/([0-9a-fA-F]{32})$")
CONNECT = re.compile(r"^/cable/connect/([0-9a-fA-F]{6})/([0-9a-fA-F]{32})$")
CONTACT = re.compile(r"^/cable/contact/[A-Za-z0-9_-]+$")

log = logging.getLogger("tunnel")


class ProtocolError(Exception):
    def __init__(self, code: int, reason: str):
        super().__init__(reason)
        self.code = code


class WebSocket:
    """The server side of one RFC 6455 connection (no extensions)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.write_lock = asyncio.Lock()
        self.closing = False

    async def _frame(self):
        head = await self.reader.readexactly(2)
        fin, rsv, opcode = head[0] & 0x80, head[0] & 0x70, head[0] & 0x0F
        masked, n = head[1] & 0x80, head[1] & 0x7F
        if rsv:
            raise ProtocolError(1002, "reserved bits set")
        if not masked:
            raise ProtocolError(1002, "client frames must be masked")
        if n == 126:
            n = struct.unpack(">H", await self.reader.readexactly(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", await self.reader.readexactly(8))[0]
        if opcode >= 8 and (n > 125 or not fin):
            raise ProtocolError(1002, "bad control frame")
        if n > MAX_MESSAGE:
            raise ProtocolError(1009, "message too big")
        key = await self.reader.readexactly(4)
        data = await self.reader.readexactly(n)
        if n:
            mask = (key * (n // 4 + 1))[:n]
            data = (int.from_bytes(data, "big") ^ int.from_bytes(mask, "big")).to_bytes(n, "big")
        return bool(fin), opcode, data

    async def recv(self):
        """The next message as (opcode, payload), or None once the connection is closed."""
        opcode, buffer = None, None
        try:
            while True:
                fin, op, data = await self._frame()
                if op == 0x8:  # close: answer it, then we are done
                    code = data[:2] if len(data) >= 2 else b""
                    await self.close(struct.unpack(">H", code)[0] if code else 1000)
                    return None
                if op == 0x9:  # ping
                    await self._send(0xA, data)
                    continue
                if op == 0xA:  # pong
                    continue
                if op in (0x1, 0x2):
                    if buffer is not None:
                        raise ProtocolError(1002, "new message inside a fragmented one")
                    opcode, buffer = op, bytearray(data)
                elif op == 0x0:
                    if buffer is None:
                        raise ProtocolError(1002, "continuation without a message")
                    buffer += data
                else:
                    raise ProtocolError(1002, f"unknown opcode {op}")
                if len(buffer) > MAX_MESSAGE:
                    raise ProtocolError(1009, "message too big")
                if fin:
                    return opcode, bytes(buffer)
        except ProtocolError as e:
            log.debug("protocol error: %s", e)
            await self.close(e.code)
            return None
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            await self.close()
            return None

    async def _send(self, opcode: int, data: bytes):
        n = len(data)
        if n < 126:
            head = struct.pack(">BB", 0x80 | opcode, n)
        elif n < 1 << 16:
            head = struct.pack(">BBH", 0x80 | opcode, 126, n)
        else:
            head = struct.pack(">BBQ", 0x80 | opcode, 127, n)
        async with self.write_lock:
            self.writer.write(head + data)
            await self.writer.drain()

    async def send(self, opcode: int, data: bytes) -> bool:
        if self.closing:
            return False
        try:
            await self._send(opcode, data)
            return True
        except (ConnectionError, OSError):
            await self.close()
            return False

    async def close(self, code: int = 1000):
        if self.closing:
            return
        self.closing = True
        try:
            await asyncio.wait_for(self._send(0x8, struct.pack(">H", code)), 2)
        except (ConnectionError, OSError, asyncio.TimeoutError):
            pass
        self.writer.close()


class Side:
    """One end of a tunnel: its WebSocket, and what it has sent that is not forwarded yet."""

    def __init__(self, ws: WebSocket):
        self.ws = ws
        self.queue: asyncio.Queue = asyncio.Queue()
        self.ended = asyncio.Event()
        self.task = asyncio.ensure_future(self._read())

    async def _read(self):
        try:
            while True:
                message = await self.ws.recv()
                if message is None:
                    break
                if self.queue.qsize() >= MAX_QUEUED:
                    await self.ws.close(1008)
                    break
                self.queue.put_nowait(message)
        finally:
            self.queue.put_nowait(None)
            self.ended.set()


class Tunnel:
    def __init__(self, routing_id: str, tunnel_id: str, phone: Side):
        self.routing_id = routing_id
        self.tunnel_id = tunnel_id
        self.phone = phone
        self.browser: "asyncio.Future[Side]" = asyncio.get_running_loop().create_future()
        self.done = asyncio.Event()


class Server:
    def __init__(self, log_addresses: bool = False):
        self.waiting: dict = {}  # routing id (hex) -> Tunnel
        self.log_addresses = log_addresses

    # ---- HTTP -----------------------------------------------------------------------

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HANDSHAKE_TIMEOUT)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                    asyncio.TimeoutError, ConnectionError, OSError):
                return
            try:
                method, path, headers = parse_request(head)
            except ValueError:
                await respond(writer, 400, "Bad Request")
                return
            if self.log_addresses:
                log.info("%s %s %s", peer[0] if peer else "?", method, path)
            await self.route(method, path, headers, reader, writer)
        finally:
            if not writer.is_closing():
                writer.close()

    async def route(self, method, path, headers, reader, writer):
        if method != "GET":
            await respond(writer, 405, "Method Not Allowed")
            return
        if path in ("/", "/health"):
            await respond(writer, 200, "caBLE tunnel server\n")
            return
        if CONTACT.match(path):
            await respond(writer, 410, "Linked phones are not supported\n")
            return
        new, connect = NEW.match(path), CONNECT.match(path)
        if not new and not connect:
            await respond(writer, 404, "Not Found")
            return
        problem = upgrade_problem(headers)
        if problem:
            await respond(writer, 400, problem + "\n")
            return
        if new:
            await self.new_tunnel(new.group(1).lower(), headers, reader, writer)
        else:
            await self.connect(connect.group(1).lower(), connect.group(2).lower(), headers, reader, writer)

    # ---- tunnels ----------------------------------------------------------------------

    async def new_tunnel(self, tunnel_id, headers, reader, writer):
        if len(self.waiting) >= MAX_WAITING:
            await respond(writer, 503, "Too many waiting tunnels\n")
            return
        routing_id = secrets.token_hex(3)
        while routing_id in self.waiting:
            routing_id = secrets.token_hex(3)
        await accept(writer, headers, {"X-Cable-Routing-Id": routing_id})
        tunnel = Tunnel(routing_id, tunnel_id, Side(WebSocket(reader, writer)))
        self.waiting[routing_id] = tunnel
        log.info("%s: phone waiting", routing_id)
        try:
            ended = asyncio.ensure_future(tunnel.phone.ended.wait())
            done, _ = await asyncio.wait({tunnel.browser, ended}, timeout=WAIT_TIMEOUT,
                                         return_when=asyncio.FIRST_COMPLETED)
            ended.cancel()
            if tunnel.browser not in done:
                log.info("%s: %s before a browser came", routing_id,
                         "phone left" if tunnel.phone.ended.is_set() else "timed out")
                tunnel.browser.cancel()
                await tunnel.phone.ws.close(1000)
                return
        finally:
            self.waiting.pop(routing_id, None)
        await self.relay(tunnel, tunnel.browser.result())

    async def connect(self, routing_id, tunnel_id, headers, reader, writer):
        tunnel = self.waiting.get(routing_id)
        if tunnel is None or tunnel.tunnel_id != tunnel_id or tunnel.browser.done():
            await respond(writer, 404, "No such tunnel\n")
            return
        await accept(writer, headers, {})
        if tunnel.browser.done():  # the phone left or timed out meanwhile
            await WebSocket(reader, writer).close(1000)
            return
        tunnel.browser.set_result(Side(WebSocket(reader, writer)))
        await tunnel.done.wait()

    async def relay(self, tunnel: Tunnel, browser: Side):
        log.info("%s: paired", tunnel.routing_id)
        started = time.monotonic()
        count = [0, 0]

        async def pump(src: Side, dst: Side, i: int):
            while True:
                message = await src.queue.get()
                if message is None or not await dst.ws.send(*message):
                    return
                count[i] += 1

        pumps = {asyncio.ensure_future(pump(tunnel.phone, browser, 0)),
                 asyncio.ensure_future(pump(browser, tunnel.phone, 1))}
        try:
            await asyncio.wait(pumps, timeout=TUNNEL_LIFETIME, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for p in pumps:
                p.cancel()
            await tunnel.phone.ws.close(1000)
            await browser.ws.close(1000)
            tunnel.done.set()
            log.info("%s: closed after %.1f s, %d messages phone->browser, %d browser->phone",
                     tunnel.routing_id, time.monotonic() - started, count[0], count[1])


# ---- HTTP helpers ---------------------------------------------------------------------

def parse_request(head: bytes):
    lines = head.decode("latin-1").split("\r\n")
    method, path, version = lines[0].split(" ")
    if not version.startswith("HTTP/1."):
        raise ValueError(version)
    headers = {}
    for line in lines[1:]:
        if line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return method, path.split("?")[0], headers


def upgrade_problem(headers):
    if headers.get("upgrade", "").lower() != "websocket":
        return "Expected a WebSocket upgrade"
    if "upgrade" not in [t.strip().lower() for t in headers.get("connection", "").split(",")]:
        return "Expected Connection: Upgrade"
    if headers.get("sec-websocket-version") != "13" or "sec-websocket-key" not in headers:
        return "Expected WebSocket version 13"
    if SUBPROTOCOL not in [p.strip() for p in headers.get("sec-websocket-protocol", "").split(",")]:
        return "Expected subprotocol " + SUBPROTOCOL
    return None


async def accept(writer, headers, extra):
    key = headers["sec-websocket-key"].encode()
    digest = base64.b64encode(hashlib.sha1(key + WS_GUID).digest()).decode()
    lines = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade",
             "Sec-WebSocket-Accept: " + digest, "Sec-WebSocket-Protocol: " + SUBPROTOCOL]
    lines += [f"{k}: {v}" for k, v in extra.items()]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
    await writer.drain()


async def respond(writer, status, body):
    reasons = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
               410: "Gone", 503: "Service Unavailable"}
    data = body.encode()
    writer.write((f"HTTP/1.1 {status} {reasons.get(status, '')}\r\nContent-Type: text/plain\r\n"
                  f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data)
    try:
        await writer.drain()
    except (ConnectionError, OSError):
        pass


# ---- main -----------------------------------------------------------------------------

async def serve(host, port, tls, log_addresses):
    server = Server(log_addresses)
    listener = await asyncio.start_server(server.handle, host, port, ssl=tls, limit=MAX_HEADER)
    for s in listener.sockets:
        log.info("listening on %s:%s%s", *s.getsockname()[:2], " (TLS)" if tls else "")
    async with listener:
        await listener.serve_forever()


def main():
    p = argparse.ArgumentParser(description="caBLE v2 (hybrid) tunnel server")
    p.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8080, help="port (default 8080)")
    p.add_argument("--tls-cert", help="certificate chain (PEM), to serve wss:// without a proxy")
    p.add_argument("--tls-key", help="private key (PEM) for --tls-cert")
    p.add_argument("--log-addresses", action="store_true", help="log client IP addresses (off by default)")
    p.add_argument("--debug", action="store_true", help="more logging")
    a = p.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.debug else logging.INFO,
                        format="%(asctime)s %(message)s")
    tls = None
    if a.tls_cert:
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(a.tls_cert, a.tls_key)
    try:
        asyncio.run(serve(a.host, a.port, tls, a.log_addresses))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
