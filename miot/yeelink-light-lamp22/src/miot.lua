-- MIoT over miIO UDP. API/layout follows wonjj6768/smartthings-miot-edge-driver.
local socket = require "cosock.socket"
local json = require "st.json"
local security = require "st.security"
local md5 = require "md5"

local miot = { MODEL = "yeelink.light.lamp22" }
local PORT = 54321
local HELLO = "\x21\x31\x00\x20" .. string.rep("\xff", 28)

local function device_error(kind, code)
  error({ miot_error = true, kind = kind, code = code }, 0)
end

function miot.error_kind(err)
  return type(err) == "table" and err.miot_error == true and err.kind or nil
end

function miot.clear(device)
  device:set_field("miot_session", nil)
end

local function exchange(ip, packet)
  local udp = assert(socket.udp(), "Cannot create UDP socket")
  local ok, result = pcall(function()
    assert(udp:setsockname("0.0.0.0", 0), "Cannot bind UDP socket")
    assert(udp:settimeout(3), "Cannot set UDP timeout")
    -- A connected UDP socket only accepts responses from the configured peer.
    assert(udp:setpeername(ip, PORT), "Cannot connect UDP socket")
    assert(udp:send(packet), "UDP send failed")
    local response = udp:receive(4096)
    assert(response, "MIoT device did not respond")
    assert(#response >= 32 and response:sub(1, 2) == "\x21\x31", "Invalid MIoT header")
    assert(string.unpack(">I2", response, 3) == #response, "Invalid MIoT length")
    return response
  end)
  udp:close()
  if not ok then error(result, 0) end
  return result
end

local function request(device, ip, token, method, params)
  local session = device:get_field("miot_session")
  if not session or session.ip ~= ip then
    local hello = exchange(ip, HELLO)
    local did, timestamp = string.unpack(">I4I4", hello, 9)
    assert(did ~= 0 and did ~= 0xffffffff, "Invalid MIoT device ID")
    session = { did = did, offset = os.time() - timestamp, ip = ip }
    device:set_field("miot_session", session)
  end
  -- A retry may have negotiated a NEW session/device. Check that session before
  -- every write, rather than relying on an earlier driver-level model check.
  if method == "set_properties" and session.model ~= miot.MODEL then
    local info = request(device, ip, token, "miIO.info", {})
    if type(info.result) ~= "table" or info.result.model ~= miot.MODEL then
      device_error("model", "unsupported_model")
    end
  end
  local id = (device:get_field("miot_message_id") or (os.time() % 10000)) + 1
  device:set_field("miot_message_id", id)
  local token_bin = md5.hex_to_bin(token)
  local key = md5.sum(token_bin)
  local iv = md5.sum(key .. token_bin)
  local options = { cipher = "aes128-cbc", iv = iv, padding = true }
  -- Match the JSON terminator used by the reference driver and python-miio.
  local payload = json.encode({ id = id, method = method, params = params }) .. "\x00"
  local encrypted = security.encrypt_bytes(payload, key, options)
  local header = string.pack(">c2I2I4I4I4", "\x21\x31", 32 + #encrypted,
    0, session.did, os.time() - session.offset)
  local response = exchange(ip, header .. md5.sum(header .. token_bin .. encrypted) .. encrypted)
  assert(string.unpack(">I4", response, 9) == session.did, "MIoT device ID mismatch")
  assert(response:sub(17, 32) == md5.sum(response:sub(1, 16) .. token_bin .. response:sub(33)),
    "MIoT response checksum mismatch")
  assert(#response > 32 and (#response - 32) % 16 == 0, "Invalid MIoT ciphertext")
  local decrypted = security.decrypt_bytes(response:sub(33), key, options):gsub("%z+$", "")
  local decoded = json.decode(decrypted)
  assert(type(decoded) == "table" and decoded.id == id, "MIoT response ID mismatch")
  if decoded.error then
    local code = type(decoded.error) == "table" and decoded.error.code or nil
    device_error("rpc", type(code) == "number" and code or nil)
  end
  if method == "miIO.info" and type(decoded.result) == "table" then
    session.model = decoded.result.model
  end
  return decoded
end

function miot.cmd(device, ip, token, method, params)
  assert(type(token) == "string" and #token == 32 and token:match("^%x+$"), "Invalid MIoT token")
  local retryable = method == "miIO.info" or method == "get_properties" or method == "set_properties"
  for attempt = 1, retryable and 2 or 1 do
    local ok, response = pcall(request, device, ip, token, method, params or {})
    if ok then return response end
    -- An authenticated rejection is a device response, not a transport failure.
    if miot.error_kind(response) then error(response, 0) end
    miot.clear(device)
    if attempt == 2 or not retryable then error(response, 0) end
  end
end

function miot.verify_model(device, ip, token)
  local session = device:get_field("miot_session")
  if session and session.ip == ip and session.model == miot.MODEL then return end
  local response = miot.cmd(device, ip, token, "miIO.info", {})
  if type(response.result) ~= "table" or response.result.model ~= miot.MODEL then
    device_error("model", "unsupported_model")
  end
end

function miot.gets(device, ip, token, properties)
  local params = {}
  for _, property in ipairs(properties) do
    params[#params + 1] = {
      did = string.format("prop.%d.%d", property.siid, property.piid),
      siid = property.siid, piid = property.piid
    }
  end
  return miot.cmd(device, ip, token, "get_properties", params)
end

function miot.set(device, ip, token, siid, piid, value)
  local response = miot.cmd(device, ip, token, "set_properties", {
    { did = string.format("set.%d.%d", siid, piid), siid = siid, piid = piid, value = value }
  })
  local status = response.result and response.result[1]
  assert(type(status) == "table" and status.siid == siid and status.piid == piid
    and type(status.code) == "number", "Invalid MIoT write response")
  if status.code ~= 0 then device_error("property", status.code) end
  return response
end

return miot
