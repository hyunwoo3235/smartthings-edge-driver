import hashlib
import json
import socket
import struct
import sys
import unittest

import yaml

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from edge_harness import DRIVER, EdgeHarness, decrypt, encrypt
from verify_device import VerificationError, require_free_scene


class DevicePeer:
    """Independent miIO packet parser/device, including AES and checksums."""
    def __init__(self):
        self.token = bytes.fromhex("12" * 16)
        self.did = 123456789
        self.properties = {1: True, 2: 80, 3: 5000, 5: 0}
        self.scene_mode = 0
        self.model = "yeelink.light.lamp22"
        self.calls = []
        self.fault = None
        self.reject_set = False
        self.reject_piid = None
        self.replace_on_write = False
        self.rpc_error = False
        self.applied = []
        self.partial = False
        self.drop_once = False
        self.saved = dict(self.properties)

    def socket(self):
        return FakeSocket(self)

    def respond(self, packet):
        if self.fault == "timeout" or self.drop_once:
            self.drop_once = False
            raise socket.timeout()
        if packet == bytes.fromhex("21310020") + b"\xff" * 28:
            return struct.pack(">HHIII", 0x2131, 32, 0, self.did, 1000) + b"\xff" * 16
        magic, size, reserved, did, timestamp = struct.unpack(">HHIII", packet[:16])
        assert (magic, size, reserved, did) == (0x2131, len(packet), 0, self.did)
        assert packet[16:32] == hashlib.md5(packet[:16] + self.token + packet[32:]).digest()
        key = hashlib.md5(self.token).digest()
        iv = hashlib.md5(key + self.token).digest()
        request = json.loads(decrypt(packet[32:], key, iv).rstrip(b"\0"))
        self.calls.append(request)
        method = request["method"]
        if method == "miIO.info":
            result = {"model": self.model, "fw_ver": "test"}
        elif method == "get_properties":
            result = [{**p, "code": 0, "value": self.scene_mode if p["siid"] == 3 else self.properties[p["piid"]]}
                      for p in request["params"]]
            if self.partial:
                result[1] = {**request["params"][1], "code": -4001}
        elif method == "set_properties":
            if self.replace_on_write:
                self.replace_on_write = False
                self.did += 1
                self.model = "yeelink.light.lamp15"
                raise socket.timeout()
            result = []
            for p in request["params"]:
                rejected = self.reject_set or p["piid"] == self.reject_piid
                if not rejected:
                    piid, value = p["piid"], p["value"]
                    if piid == 1 and value is False:
                        self.saved = dict(self.properties)
                    if piid == 1 and value is True and not self.properties[1]:
                        # Real lamp restores its previous light settings when turned on.
                        self.properties.update({2: self.saved[2], 3: self.saved[3]})
                    self.properties[piid] = value
                    self.applied.append((self.model, piid, value))
                result.append({k: v for k, v in p.items() if k != "value"})
                result[-1]["code"] = -4004 if rejected else 0
        else:
            raise AssertionError(method)
        response = {"id": request["id"], "result": result}
        if self.rpc_error:
            response = {"id": request["id"], "error": {"code": -32601, "message": "unsupported method"}}
        if self.fault == "id":
            response["id"] += 1
        data = encrypt(json.dumps(response).encode() + b"\0", key, iv)
        header = struct.pack(">HHIII", 0x2131, 32 + len(data), 0,
                             self.did + (self.fault == "device_id"), timestamp)
        checksum = hashlib.md5(header + self.token + data).digest()
        if self.fault == "checksum":
            checksum = b"\0" * 16
        if self.fault == "length":
            header = header[:2] + b"\0\x20" + header[4:]
        return header + checksum + data


class FakeSocket:
    def __init__(self, peer):
        self.peer = peer
        self.closed = False

    def bind(self, address):
        self.local = address

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.address = address

    def send(self, packet):
        self.packet = packet
        return len(packet)

    def recv(self, size):
        return self.peer.respond(self.packet)

    def close(self):
        self.closed = True


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.peer = DevicePeer()
        self.h = EdgeHarness(token=self.peer.token.hex(), socket_factory=self.peer.socket)

    def tearDown(self):
        self.assertTrue(all(s.closed for s in self.h.sockets), "UDP socket leaked")

    def test_md5_vectors(self):
        md5 = self.h.lua.eval(b'require "md5"')
        for message in (b"", b"a", b"abc", b"a" * 55, b"a" * 56, b"a" * 128, bytes(range(256))):
            self.assertEqual(md5[b"sum"](message), hashlib.md5(message).digest())

    def test_init_reads_confirmed_values_and_range(self):
        self.h.lifecycle("added")
        self.h.lifecycle("init")
        values = self.h.values()
        self.assertEqual(values["switch"], "on")
        self.assertEqual(values["level"], 80)
        self.assertEqual(values["colorTemperature"], 5000)
        self.assertEqual(values["colorTemperatureRange"]["value"], {"minimum": 2700, "maximum": 6500})
        self.assertTrue(self.h.device[b"online_state"])

    def test_power_and_zero_level_preserve_dim_value(self):
        self.h.lifecycle("init")
        self.h.command("switchLevel", "setLevel", level=0)
        self.h.flush()
        self.assertEqual(self.peer.properties, {1: False, 2: 80, 3: 5000, 5: 0})
        self.assertEqual(self.h.values()["switch"], "off")
        self.assertEqual(self.h.values()["level"], 80)
        self.h.command("switch", "on")
        self.h.flush()
        self.assertIs(self.peer.properties[1], True)

    def test_level_clamps_rounds_and_turns_on(self):
        self.peer.properties[1] = False
        for level, expected in ((42.6, 43), (150, 100), (1, 1)):
            self.h.command("switchLevel", "setLevel", level=level)
            self.h.flush()
            self.assertEqual(self.peer.properties[2], expected)
            self.assertIs(self.peer.properties[1], True)
            self.assertEqual(self.h.values()["level"], expected)

    def test_temperature_clamps_and_turns_on(self):
        self.peer.properties[1] = False
        for temperature, expected in ((2000, 2700), (4000.2, 4000), (7000, 6500)):
            self.h.command("colorTemperature", "setColorTemperature", temperature=temperature)
            self.h.flush()
            self.assertEqual(self.peer.properties[3], expected)
            self.assertIs(self.peer.properties[1], True)
            self.assertEqual(self.h.values()["colorTemperature"], expected)

    def test_rejected_write_does_not_emit_success(self):
        self.h.lifecycle("init")
        event_count = len(self.h.device[b"events"])
        self.peer.reject_set = True
        self.h.command("switch", "off")
        self.assertEqual(len(self.h.device[b"events"]), event_count)
        self.assertIs(self.peer.properties[1], True)
        self.assertNotIn(self.peer.token.hex(), "\n".join(self.h.logs))

    def test_partial_reads_fail_then_recover(self):
        self.h.lifecycle("init")
        self.peer.partial = True
        for _ in range(3):
            self.h.command("refresh", "refresh")
        self.assertFalse(self.h.device[b"online_state"])
        self.assertEqual(self.h.values()["level"], 80)
        self.peer.partial = False
        self.h.command("refresh", "refresh")
        self.assertTrue(self.h.device[b"online_state"])
        self.assertEqual(self.h.device[b"fields"][b"communication_failures"], 0)

    def test_rejected_commands_do_not_mark_reachable_lamp_offline(self):
        self.h.lifecycle("init")
        self.peer.reject_set = True
        for _ in range(3):
            self.h.command("switch", "off")
        self.assertTrue(self.h.device[b"online_state"])
        self.assertEqual(self.h.device[b"fields"][b"communication_failures"], 0)

    def test_partial_command_reads_back_actual_power(self):
        self.peer.properties[1] = False
        self.h.lifecycle("init")
        self.peer.reject_piid = 2
        self.h.command("switchLevel", "setLevel", level=50)
        self.h.flush()
        self.assertTrue(self.peer.properties[1])
        self.assertEqual(self.h.values()["switch"], "on")
        self.assertEqual(self.h.values()["level"], 80)
        self.peer.reject_piid = None
        self.h.command("switch", "off")
        self.peer.reject_piid = 3
        self.h.command("colorTemperature", "setColorTemperature", temperature=4000)
        self.h.flush()
        self.assertEqual(self.h.values()["switch"], "on")
        self.assertEqual(self.h.values()["colorTemperature"], 5000)

    def test_retry_reverifies_model_before_write(self):
        self.h.lifecycle("init")
        self.peer.replace_on_write = True
        self.h.command("switch", "off")
        self.assertEqual(self.peer.applied, [])
        self.assertFalse(self.h.device[b"online_state"])

    def test_retry_reverifies_model_when_device_id_is_unchanged(self):
        self.h.lifecycle("init")
        self.h.miot[b"clear"](self.h.device)
        self.peer.model = "yeelink.light.lamp15"
        prefs = self.h.device[b"preferences"]
        with self.assertRaises(Exception):
            self.h.miot[b"set"](self.h.device, prefs[b"ipAddress"], prefs[b"token"], 2, 1, False)
        self.assertEqual(self.peer.applied, [])

    def test_authenticated_rpc_rejection_is_not_retried(self):
        self.h.lifecycle("init")
        self.peer.rpc_error = True
        before_calls = len(self.peer.calls)
        self.h.command("switch", "off")
        self.assertEqual(len(self.peer.calls), before_calls + 1)
        self.assertTrue(self.h.device[b"online_state"])
        self.assertIn("-32601", self.h.logs[-1])

    def test_malformed_numeric_readback_emits_no_partial_events(self):
        self.h.lifecycle("init")
        for piid, value in ((2, 50.5), (3, 4000.5), (2, float("inf"))):
            before_events = len(self.h.device[b"events"])
            old_value = self.peer.properties[piid]
            self.peer.properties[piid] = value
            self.h.command("refresh", "refresh")
            self.assertEqual(len(self.h.device[b"events"]), before_events)
            self.peer.properties[piid] = old_value

    def test_exercise_refuses_custom_scenes_hidden_by_generic_mode(self):
        require_free_scene(self.h)
        self.peer.scene_mode = 1
        with self.assertRaises(VerificationError):
            require_free_scene(self.h)
        self.assertEqual(self.peer.applied, [])

    def test_response_integrity_errors_retry_and_close_sockets(self):
        for fault in ("checksum", "id", "device_id", "length", "timeout"):
            with self.subTest(fault=fault):
                self.peer.fault = fault
                with self.assertRaises(Exception):
                    self.h.rpc("miIO.info")
                self.assertTrue(all(s.closed for s in self.h.sockets))
        self.peer.fault = None
        self.assertEqual(self.h.rpc("miIO.info")["result"]["model"], self.peer.model)

    def test_transient_timeout_recovers(self):
        self.peer.drop_once = True
        self.h.lifecycle("init")
        self.assertTrue(self.h.device[b"online_state"])

    def test_wrong_model_never_receives_write(self):
        self.peer.model = "yeelink.light.lamp15"
        self.h.command("switch", "off")
        self.assertFalse(any(c["method"] == "set_properties" for c in self.peer.calls))
        self.assertFalse(self.h.device[b"online_state"])

    def test_invalid_preferences_do_not_send_packets(self):
        for ip, token in (("999.1.1.1", "12" * 16), ("192.0.2.1", "x" * 32), ("", "")):
            self.h.device[b"preferences"][b"ipAddress"] = ip.encode()
            self.h.device[b"preferences"][b"token"] = token.encode()
            self.h.lifecycle("init")
            self.h.command("switch", "on")
        self.assertEqual(len(self.h.sockets), 0)

    def test_preference_change_replaces_timers_and_session(self):
        self.h.lifecycle("init")
        original = self.h.device[b"fields"][b"polling_timer"]
        old_preferences = self.h.to_python(self.h.device[b"preferences"])
        self.h.device[b"preferences"][b"pollingInterval"] = 10
        self.h.device[b"preferences"][b"ipAddress"] = b"192.0.2.2"
        self.h.lifecycle("infoChanged", {"old_st_store": {"preferences": old_preferences}})
        self.assertTrue(original[b"cancelled"])
        self.assertEqual(self.h.device[b"fields"][b"polling_timer"][b"interval"], 10)
        self.assertEqual(self.h.sockets[-1].address, ("192.0.2.2", 54321))
        self.assertEqual(sum(c["method"] == "miIO.info" for c in self.peer.calls), 2)
        self.h.command("switch", "off")
        self.h.lifecycle("removed")
        self.assertIsNone(self.h.device[b"fields"][b"polling_timer"])
        self.assertIsNone(self.h.device[b"fields"][b"refresh_timer"])

    def test_manual_discovery_and_extra_device(self):
        self.h.driver[b"discovery"](self.h.driver)
        first = self.h.to_python(self.h.driver[b"created"])[0]
        self.assertEqual(first["profile"], "yeelink-light-lamp22")
        self.h.driver[b"devices"][1] = self.h.device
        self.h.driver[b"discovery"](self.h.driver)
        self.assertEqual(len(self.h.driver[b"created"]), 1)
        old_preferences = self.h.to_python(self.h.device[b"preferences"])
        self.h.device[b"preferences"][b"createDev"] = True
        self.h.lifecycle("infoChanged", {"old_st_store": {"preferences": old_preferences}})
        created = self.h.to_python(self.h.driver[b"created"])
        self.assertEqual(len(created), 2)
        self.assertNotEqual(created[0]["device_network_id"], created[1]["device_network_id"])

    def test_missing_old_preferences_does_not_create_extra_device(self):
        self.h.device[b"preferences"][b"createDev"] = True
        self.h.lifecycle("infoChanged")
        self.assertEqual(len(self.h.driver[b"created"]), 0)

    def test_profile_matches_registered_handlers(self):
        profile = yaml.safe_load((DRIVER / "profiles" / "yeelink-light-lamp22.yaml").read_text())
        config = yaml.safe_load((DRIVER / "config.yml").read_text())
        self.assertEqual(profile["name"], "yeelink-light-lamp22")
        self.assertEqual(set(config["permissions"]), {"lan", "discovery"})
        declared = {c["id"] for c in profile["components"][0]["capabilities"]}
        self.assertEqual(declared, set(self.h.to_python(self.h.driver[b"capability_handlers"])))


if __name__ == "__main__":
    unittest.main()
