"""Cross-check Lua packets using the published python-miio codec, not our codec."""
import struct
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from miio.protocol import Message, Utils

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from edge_harness import EdgeHarness
from test_driver import FakeSocket


class PublicProtocolPeer:
    def __init__(self):
        self.token = bytes.fromhex("34" * 16)
        self.properties = {1: True, 2: 80, 3: 5000}
        self.requests = []

    def socket(self):
        return FakeSocket(self)

    def respond(self, packet):
        if len(packet) == 32:
            return struct.pack(">HHIII", 0x2131, 32, 0, 123456789, 1000) + b"\xff" * 16
        # Public library validates checksum, decrypts AES, strips NUL, parses JSON.
        parsed = Message.parse(packet, token=self.token)
        request = parsed.data.value
        self.requests.append(request)
        assert Utils.decrypt(packet[32:], self.token).endswith(b"\0")
        method = request["method"]
        if method == "miIO.info":
            result = {"model": "yeelink.light.lamp22"}
        elif method == "get_properties":
            result = [{**p, "code": 0, "value": self.properties[p["piid"]]}
                      for p in request["params"]]
        elif method == "set_properties":
            result = []
            for p in request["params"]:
                self.properties[p["piid"]] = p["value"]
                result.append({"did": p["did"], "siid": p["siid"], "piid": p["piid"], "code": 0})
        else:
            raise AssertionError("Unexpected RPC method")
        # The public builder creates all reply ciphertext/checksums/padding.
        return Message.build({
            "header": {"value": {
                "device_id": parsed.header.value.device_id,
                "ts": datetime.fromtimestamp(1000, timezone.utc),
            }},
            "data": {"value": {"id": request["id"], "result": result}},
            "checksum": 0,
        }, token=self.token)


class PublicProtocolTests(unittest.TestCase):
    def test_lua_commands_interoperate_with_python_miio_packets(self):
        peer = PublicProtocolPeer()
        h = EdgeHarness(token=peer.token.hex(), socket_factory=peer.socket)
        h.lifecycle("init")
        self.assertTrue(h.device[b"online_state"])
        for cap, command, args, attribute, expected in (
            ("switch", "off", {}, "switch", "off"),
            ("switchLevel", "setLevel", {"level": 65}, "level", 65),
            ("colorTemperature", "setColorTemperature", {"temperature": 4500}, "colorTemperature", 4500),
        ):
            h.command(cap, command, **args)
            h.flush()
            self.assertEqual(h.values()[attribute], expected)
        self.assertFalse(h.logs)
        self.assertTrue(all(s.closed for s in h.sockets))

    def test_wrong_token_cannot_parse_lua_packet(self):
        peer = PublicProtocolPeer()
        h = EdgeHarness(token=peer.token.hex(), socket_factory=peer.socket)
        h.lifecycle("init")
        packet = h.sockets[-1].packet
        with self.assertRaises(Exception):
            Message.parse(packet, token=bytes.fromhex("56" * 16))


if __name__ == "__main__":
    unittest.main()
