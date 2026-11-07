#!/usr/bin/env python3
"""Verify the shipped Lua driver on a LAN lamp; optionally exercise and restore it."""
import argparse
import getpass
import json
import os
import sys
import time

from edge_harness import EdgeHarness


class VerificationError(RuntimeError):
    pass


def require_free_scene(h):
    properties = [(2, 5), (3, 9)]
    response = h.rpc("get_properties", [
        {"did": f"prop.{siid}.{piid}", "siid": siid, "piid": piid} for siid, piid in properties
    ])
    values = {(p.get("siid"), p.get("piid")): p.get("value")
              for p in response.get("result", []) if p.get("code") == 0}
    if any(values.get(prop) != 0 for prop in properties):
        raise VerificationError("Exercise requires free scene mode (2/5=0 and 3/9=0); no preset will be overwritten")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default=os.environ.get("MIOT_IP"), required=not os.environ.get("MIOT_IP"))
    parser.add_argument("--expected-id", type=int, help="Require a matching miIO device ID before writes")
    parser.add_argument("--exercise", action="store_true", help="Test power, dimming and temperature; restore in finally")
    parser.add_argument("--reference", action="store_true", help="Independently read every tested state with python-miio")
    args = parser.parse_args()
    token = os.environ.get("MIOT_TOKEN") or getpass.getpass("MIoT token (hidden): ")
    if len(token) != 32 or any(c not in "0123456789abcdefABCDEF" for c in token):
        parser.error("Token must contain 32 hex digits")
    h = EdgeHarness(ip=args.ip, token=token)
    info = h.rpc("miIO.info")["result"]
    if info.get("model") != "yeelink.light.lamp22":
        raise VerificationError("Unexpected model; no changes made")
    session = h.to_python(h.device[b"fields"][b"miot_session"])
    if args.expected_id is not None and session["did"] != args.expected_id:
        raise VerificationError("Device ID does not match; no changes made")
    print(json.dumps({"model": info["model"], "firmware": info.get("fw_ver"),
                      "device_id": session["did"]}, ensure_ascii=False))
    h.lifecycle("added")
    h.lifecycle("init")
    if not h.device[b"online_state"]:
        raise VerificationError("Lua driver could not read all three light properties")
    original = h.values()
    print("Initial:", json.dumps(original, ensure_ascii=False))
    reference = None
    if args.reference:
        from miio_reference import MiioReference
        reference = MiioReference(args.ip, token)

    def check_reference():
        if reference is None:
            return
        expected = {key: h.values()[key] for key in ("switch", "level", "colorTemperature")}
        actual = reference.read()
        if actual != expected:
            raise VerificationError("python-miio readback differs from the Lua driver")
        print("PASS python-miio:", json.dumps(actual))

    check_reference()
    if not args.exercise:
        h.lifecycle("removed")
        return

    # Custom scenes use service 3/9 and can still report generic mode 2/5=0.
    # Avoid overwriting a preset that cannot be restored exactly from core values.
    require_free_scene(h)

    def check(capability, command, attribute, expected, **kwargs):
        before_logs = len(h.logs)
        h.command(capability, command, **kwargs)
        time.sleep(1.1)
        h.flush()
        values = h.values()
        must_be_on = capability == "colorTemperature" or (capability == "switchLevel" and kwargs["level"] > 0)
        if values.get(attribute) != expected or len(h.logs) != before_logs or (must_be_on and values.get("switch") != "on"):
            raise VerificationError(f"Readback did not confirm {command}")
        check_reference()
        print(f"PASS {command}: {attribute}={expected}")

    try:
        check("switch", "off", "switch", "off")
        check("switch", "on", "switch", "on")
        test_level = 75 if original["level"] != 75 else 80
        check("switchLevel", "setLevel", "level", test_level, level=test_level)
        check("switch", "off", "switch", "off")
        test_temperature = 4000 if original["colorTemperature"] != 4000 else 4500
        check("colorTemperature", "setColorTemperature", "colorTemperature", test_temperature,
              temperature=test_temperature)
        check("switchLevel", "setLevel", "switch", "off", level=0)
        second_level = 70 if test_level != 70 else 65
        check("switchLevel", "setLevel", "level", second_level, level=second_level)
    finally:
        # Restore each property independently so a failed restoration does not skip the rest.
        errors = []
        restore = [(1, True), (2, original["level"]), (3, original["colorTemperature"])]
        restore.append((1, original["switch"] == "on"))
        prefs = h.device[b"preferences"]
        for piid, value in restore:
            try:
                h.miot[b"set"](h.device, prefs[b"ipAddress"], prefs[b"token"], 2, piid, value)
            except Exception:
                errors.append(piid)
        time.sleep(1.1)
        before_logs = len(h.logs)
        before_events = len(h.device[b"events"])
        h.command("refresh", "refresh")
        restored = h.values()
        h.lifecycle("removed")
        fresh_read = len(h.logs) == before_logs and len(h.device[b"events"]) == before_events + 3
        if errors or not fresh_read or any(restored.get(k) != original[k] for k in ("switch", "level", "colorTemperature")):
            raise VerificationError(f"Restore not confirmed; failed property IDs: {errors}")
        require_free_scene(h)
        check_reference()
        print("Restored:", json.dumps(restored, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except VerificationError as error:
        print(f"Verification failed: {error}", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        # No raw SDK/crypto exceptions or credentials in command output.
        print(f"Verification failed ({type(error).__name__}). Check connectivity and device state.", file=sys.stderr)
        sys.exit(1)
