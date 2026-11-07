"""Run the shipped Lua 5.3 source with host socket/crypto/Edge SDK adapters.

This is a local test harness, not a SmartThings Hub emulator. In particular,
SmartThings lifecycle dispatch, cosock scheduling, and mobile UI need a real Hub.
"""
import json
import socket
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from lupa.lua53 import LuaRuntime, lua_type

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "miot" / "yeelink-light-lamp22"


def encrypt(data, key, iv):
    padder = PKCS7(128).padder()
    data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return cipher.update(data) + cipher.finalize()


def decrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = cipher.update(data) + cipher.finalize()
    padder = PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()


class EdgeHarness:
    def __init__(self, ip="192.0.2.1", token="00" * 16, socket_factory=None):
        self.lua = LuaRuntime(encoding=None, unpack_returned_tuples=True)
        self.logs = []
        self.sockets = []
        self.socket_factory = socket_factory or (lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        globals_ = self.lua.globals()
        globals_.host_udp = self._udp
        globals_.host_encode = lambda data: json.dumps(self.to_python(data), separators=(",", ":")).encode()
        globals_.host_decode = lambda data: self.to_lua(json.loads(data))
        globals_.host_encrypt = lambda data, key, options: encrypt(data, key, options[b"iv"])
        globals_.host_decrypt = lambda data, key, options: decrypt(data, key, options[b"iv"])
        globals_.host_warn = lambda message: self.logs.append(message.decode())
        globals_.source_dir = str(DRIVER / "src").encode()
        self.lua.execute(b'''
          package.path = source_dir .. "/?.lua;" .. package.path
          package.preload["cosock.socket"] = function() return { udp = host_udp } end
          package.preload["st.json"] = function()
            return { encode = host_encode, decode = host_decode }
          end
          package.preload["st.security"] = function()
            return { encrypt_bytes = host_encrypt, decrypt_bytes = host_decrypt }
          end
          package.preload["log"] = function() return { warn = host_warn } end
          package.preload["st.capabilities"] = function()
            local function attribute(cap, name)
              return setmetatable({}, { __call = function(_, value)
                return { capability = cap, attribute = name, value = value }
              end })
            end
            local switch = attribute("switch", "switch")
            switch.on = function() return switch("on") end
            switch.off = function() return switch("off") end
            return {
              switch = { ID = "switch", switch = switch,
                commands = { on = { NAME = "on" }, off = { NAME = "off" } } },
              switchLevel = { ID = "switchLevel", level = attribute("switchLevel", "level"),
                commands = { setLevel = { NAME = "setLevel" } } },
              colorTemperature = { ID = "colorTemperature",
                colorTemperature = attribute("colorTemperature", "colorTemperature"),
                colorTemperatureRange = attribute("colorTemperature", "colorTemperatureRange"),
                commands = { setColorTemperature = { NAME = "setColorTemperature" } } },
              refresh = { ID = "refresh", commands = { refresh = { NAME = "refresh" } } }
            }
          end
          package.preload["st.driver"] = function()
            return function(name, template)
              driver_under_test = template
              template.devices = {}
              template.created = {}
              function template:run() end
              function template:get_devices() return self.devices end
              function template:try_create_device(metadata)
                self.created[#self.created + 1] = metadata
                return true
              end
              return template
            end
          end
          function make_device(preferences)
            local device = { preferences = preferences, fields = {}, events = {}, online_state = false }
            function device:get_field(key) return self.fields[key] end
            function device:set_field(key, value) self.fields[key] = value end
            function device:emit_event(event) self.events[#self.events + 1] = event end
            function device:online() self.online_state = true end
            function device:offline() self.online_state = false end
            device.thread = { timers = {} }
            function device.thread:call_on_schedule(interval, callback, name)
              local timer = { interval = interval, callback = callback, recurring = true, name = name }
              self.timers[#self.timers + 1] = timer
              return timer
            end
            function device.thread:call_with_delay(interval, callback, name)
              local timer = { interval = interval, callback = callback, name = name }
              self.timers[#self.timers + 1] = timer
              return timer
            end
            function device.thread:cancel_timer(timer) timer.cancelled = true end
            function device.thread:flush_delays()
              local pending = self.timers
              self.timers = {}
              for _, timer in ipairs(pending) do
                if timer.recurring and not timer.cancelled then
                  self.timers[#self.timers + 1] = timer
                elseif not timer.cancelled then timer.callback() end
              end
            end
            return device
          end
        ''')
        self.lua.execute((DRIVER / "src" / "init.lua").read_bytes())
        self.driver = globals_.driver_under_test
        self.device = globals_.make_device(self.to_lua({
            "ipAddress": ip, "token": token, "pollingInterval": 60, "createDev": False
        }))
        self.miot = self.lua.eval(b'require "miot"')

    def to_lua(self, value):
        if isinstance(value, dict):
            return self.lua.table_from({self.to_lua(k): self.to_lua(v) for k, v in value.items()})
        if isinstance(value, list):
            return self.lua.table_from([self.to_lua(item) for item in value])
        return value.encode() if isinstance(value, str) else value

    def to_python(self, value):
        if lua_type(value) == "table":
            items = list(value.items())
            if items and all(isinstance(k, int) for k, _ in items):
                return [self.to_python(value[i]) for i in range(1, len(items) + 1)]
            return {self.to_python(k): self.to_python(v) for k, v in items}
        return value.decode() if isinstance(value, bytes) else value

    def _udp(self):
        sock = self.socket_factory()
        self.sockets.append(sock)

        def method(callback):
            def invoke(_, *args):
                try:
                    result = callback(*args)
                    return 1 if result is None else result
                except OSError:
                    return None
            return invoke

        return self.lua.table_from({
            b"setsockname": method(lambda ip, port: sock.bind((ip.decode(), port))),
            b"settimeout": method(sock.settimeout),
            b"setpeername": method(lambda ip, port: sock.connect((ip.decode(), port))),
            b"send": method(sock.send),
            b"receive": method(sock.recv),
            b"close": method(sock.close),
        })

    def lifecycle(self, name, args=None):
        return self.driver[b"lifecycle_handlers"][name.encode()](
            self.driver, self.device, None, self.to_lua(args or {}))

    def command(self, capability, command, **args):
        return self.driver[b"capability_handlers"][capability.encode()][command.encode()](
            self.driver, self.device, self.to_lua({"args": args}))

    def flush(self):
        thread = self.device[b"thread"]
        thread[b"flush_delays"](thread)

    def rpc(self, method, params=None):
        prefs = self.device[b"preferences"]
        return self.to_python(self.miot[b"cmd"](
            self.device, prefs[b"ipAddress"], prefs[b"token"], method.encode(), self.to_lua(params or {})))

    def values(self):
        values = {}
        for event in self.to_python(self.device[b"events"]):
            values[event["attribute"]] = event["value"]
        return values
