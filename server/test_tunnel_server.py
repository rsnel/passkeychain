#!/usr/bin/env python3
"""Tests for tunnel-server.py and tunnel-hostnames.py: python3 -m unittest -v (in this directory)."""

import asyncio
import base64
import hashlib
import importlib.util
import os
import pathlib
import struct
import unittest

HERE = pathlib.Path(__file__).parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ts = load("tunnel_server", "tunnel-server.py")
th = load("tunnel_hostnames", "tunnel-hostnames.py")

TUNNEL_ID = "00112233445566778899aabbccddeeff"


OPEN = []


class Client:
    """A minimal WebSocket client, enough to play phone or browser."""

    async def open(self, port, path, protocol="fido.cable"):
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", port)
        OPEN.append(self.writer)
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [f"GET {path} HTTP/1.1", "Host: localhost", "Upgrade: websocket", "Connection: Upgrade",
                 "Sec-WebSocket-Key: " + key, "Sec-WebSocket-Version: 13"]
        if protocol:
            lines.append("Sec-WebSocket-Protocol: " + protocol)
        self.writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
        head = (await self.reader.readuntil(b"\r\n\r\n")).decode()
        status = int(head.split(" ")[1])
        self.headers = {}
        for line in head.split("\r\n")[1:]:
            if line:
                k, _, v = line.partition(":")
                self.headers[k.strip().lower()] = v.strip()
        if status == 101:
            want = base64.b64encode(hashlib.sha1(key.encode() + ts.WS_GUID).digest()).decode()
            assert self.headers["sec-websocket-accept"] == want
        return status

    def frame(self, opcode, data, fin=True):
        n = len(data)
        first = (0x80 if fin else 0) | opcode
        if n < 126:
            head = struct.pack(">BB", first, 0x80 | n)
        elif n < 1 << 16:
            head = struct.pack(">BBH", first, 0x80 | 126, n)
        else:
            head = struct.pack(">BBQ", first, 0x80 | 127, n)
        key = os.urandom(4)
        self.writer.write(head + key + bytes(b ^ key[i % 4] for i, b in enumerate(data)))

    async def recv(self):
        """(opcode, data) of the next frame, or None when the connection ended."""
        try:
            head = await asyncio.wait_for(self.reader.readexactly(2), 5)
        except asyncio.IncompleteReadError:
            return None
        n = head[1] & 0x7F
        if n == 126:
            n = struct.unpack(">H", await self.reader.readexactly(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", await self.reader.readexactly(8))[0]
        return head[0] & 0x0F, await self.reader.readexactly(n)


class TunnelServerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = ts.Server()
        self.listener = await asyncio.start_server(self.server.handle, "127.0.0.1", 0, limit=ts.MAX_HEADER)
        self.port = self.listener.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        while OPEN:
            OPEN.pop().close()
        await asyncio.sleep(0.05)
        self.listener.close()
        await self.listener.wait_closed()

    async def pair(self):
        phone, browser = Client(), Client()
        self.assertEqual(await phone.open(self.port, "/cable/new/" + TUNNEL_ID.upper()), 101)
        self.assertEqual(phone.headers["sec-websocket-protocol"], "fido.cable")
        routing = phone.headers["x-cable-routing-id"]
        self.assertRegex(routing, r"^[0-9a-f]{6}$")
        self.assertEqual(await browser.open(self.port, f"/cable/connect/{routing}/{TUNNEL_ID}"), 101)
        return phone, browser

    async def test_relays_both_ways(self):
        phone, browser = await self.pair()
        browser.frame(0x2, b"msg1")
        self.assertEqual(await phone.recv(), (0x2, b"msg1"))
        phone.frame(0x2, b"msg2")
        self.assertEqual(await browser.recv(), (0x2, b"msg2"))
        # fragmented, and large enough for the 64-bit length
        big = os.urandom(70000)
        phone.frame(0x2, big[:30000], fin=False)
        phone.frame(0x0, big[30000:])
        self.assertEqual(await browser.recv(), (0x2, big))

    async def test_message_sent_before_the_browser_arrives_is_kept(self):
        phone = Client()
        await phone.open(self.port, "/cable/new/" + TUNNEL_ID)
        phone.frame(0x2, b"early")
        await asyncio.sleep(0.1)
        browser = Client()
        await browser.open(self.port, f"/cable/connect/{phone.headers['x-cable-routing-id']}/{TUNNEL_ID}")
        self.assertEqual(await browser.recv(), (0x2, b"early"))

    async def test_ping_is_answered_not_forwarded(self):
        phone, browser = await self.pair()
        phone.frame(0x9, b"hi")
        self.assertEqual(await phone.recv(), (0xA, b"hi"))
        phone.frame(0x2, b"after")
        self.assertEqual(await browser.recv(), (0x2, b"after"))

    async def test_closing_one_side_closes_the_other(self):
        phone, browser = await self.pair()
        phone.frame(0x8, struct.pack(">H", 1000))
        self.assertEqual((await phone.recv())[0], 0x8)
        self.assertEqual((await browser.recv())[0], 0x8)
        self.assertIsNone(await browser.recv())

    async def test_wrong_tunnel_id_is_refused(self):
        phone = Client()
        await phone.open(self.port, "/cable/new/" + TUNNEL_ID)
        routing = phone.headers["x-cable-routing-id"]
        self.assertEqual(await Client().open(self.port, f"/cable/connect/{routing}/{'0' * 32}"), 404)
        self.assertEqual(await Client().open(self.port, f"/cable/connect/000000/{TUNNEL_ID}"),
                         101 if routing == "000000" else 404)

    async def test_second_browser_is_refused(self):
        phone, browser = await self.pair()
        routing = phone.headers["x-cable-routing-id"]
        self.assertEqual(await Client().open(self.port, f"/cable/connect/{routing}/{TUNNEL_ID}"), 404)

    async def test_subprotocol_required(self):
        self.assertEqual(await Client().open(self.port, "/cable/new/" + TUNNEL_ID, protocol=None), 400)

    async def test_contact_and_unknown_paths(self):
        self.assertEqual(await Client().open(self.port, "/cable/contact/abc_-1"), 410)
        self.assertEqual(await Client().open(self.port, "/cable/new/xyz"), 404)
        self.assertEqual(await Client().open(self.port, "/"), 200)

    async def test_unmasked_frame_closes(self):
        phone, browser = await self.pair()
        phone.writer.write(b"\x82\x02hi")  # no mask bit
        op, data = await phone.recv()
        self.assertEqual((op, struct.unpack(">H", data)[0]), (0x8, 1002))


class HostnamesTest(unittest.TestCase):
    def test_chromium_vector(self):
        # Chromium device/fido/cable/v2_handshake_unittest.cc
        self.assertEqual(th.hostname(266), "cable.wufkweyy3uaxb.com")

    def test_range(self):
        with self.assertRaises(ValueError):
            th.hostname(255)
        self.assertTrue(th.hostname(65535).startswith("cable."))
        self.assertEqual(th.registrable("cable.wufkweyy3uaxb.com"), "wufkweyy3uaxb.com")


if __name__ == "__main__":
    unittest.main()
