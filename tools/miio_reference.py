"""Independent device reads through the published python-miio library."""
from miio.miot_device import MiotDevice

# Exact-model mapping also used by shaarkys/com.xiaomi-miio's lamp22 driver.
MAPPING = {
    "power": {"siid": 2, "piid": 1},
    "brightness": {"siid": 2, "piid": 2},
    "color_temperature": {"siid": 2, "piid": 3},
}


class MiioReference:
    def __init__(self, ip, token):
        self.device = MiotDevice(ip, token, mapping=MAPPING, timeout=3)
        if self.device.info().model != "yeelink.light.lamp22":
            raise RuntimeError("python-miio reported an unexpected model")

    def read(self):
        result = self.device.get_properties_for_mapping()
        values = {p.get("did"): p.get("value") for p in result if p.get("code") == 0}
        if set(values) != set(MAPPING) or type(values["power"]) is not bool:
            raise RuntimeError("python-miio could not read all mapped properties")
        return {
            "switch": "on" if values["power"] else "off",
            "level": values["brightness"],
            "colorTemperature": values["color_temperature"],
        }
