local capabilities = require "st.capabilities"
local Driver = require "st.driver"
local log = require "log"
local discovery = require "discovery"
local miot = require "miot"

local PROPERTIES = {
  { siid = 2, piid = 1 }, -- power (bool)
  { siid = 2, piid = 2 }, -- brightness (1..100)
  { siid = 2, piid = 3 }  -- color temperature (2700..6500 K)
}

local function config(device)
  local preferences = device.preferences or {}
  local ip, token = preferences.ipAddress, preferences.token
  if type(ip) ~= "string" or type(token) ~= "string" then return end
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if a < 1 or a > 223 or b > 255 or c > 255 or d > 255 then return end
  if #token ~= 32 or not token:match("^%x+$") then return end
  return ip, token
end

local function integer(value, minimum, maximum)
  assert(type(value) == "number" and value == value, "Invalid numeric command")
  return math.floor(math.max(minimum, math.min(maximum, value)) + 0.5)
end

-- Never include preferences, tokens, payloads, or raw SDK errors in log messages.
local function perform(device, operation, callback)
  local ip, token = config(device)
  if not ip then
    device:offline()
    log.warn("Light Bar 1S: enter a valid IPv4 address and 32-digit hex token")
    return false
  end
  local ok, err = pcall(function()
    miot.verify_model(device, ip, token)
    callback(ip, token)
  end)
  local kind = miot.error_kind(err)
  if ok then
    device:set_field("communication_failures", 0)
  elseif kind == "model" then
    device:set_field("communication_failures", 0)
    device:offline()
    log.warn("Light Bar 1S: the configured IP belongs to an unsupported model")
  elseif kind == "rpc" or kind == "property" then
    device:set_field("communication_failures", 0)
    local code = type(err.code) == "number" and tostring(err.code) or "unknown"
    log.warn("Light Bar 1S: " .. operation .. " rejected by device (MIoT code " .. code .. ")")
  else
    local failures = (device:get_field("communication_failures") or 0) + 1
    device:set_field("communication_failures", failures)
    if failures >= 3 then device:offline() end
    log.warn("Light Bar 1S: " .. operation .. " failed; check device, IP, token and LAN connectivity")
  end
  return ok
end

local function poll(device)
  return perform(device, "refresh", function(ip, token)
    local response = miot.gets(device, ip, token, PROPERTIES)
    local values = {}
    for _, property in ipairs(response.result or {}) do
      if property.siid == 2 and property.code == 0 then
        values[property.piid] = property.value
      end
    end
    assert(type(values[1]) == "boolean", "Missing power status")
    assert(type(values[2]) == "number" and values[2] >= 1 and values[2] <= 100 and values[2] % 1 == 0,
      "Missing brightness status")
    assert(type(values[3]) == "number" and values[3] >= 2700 and values[3] <= 6500 and values[3] % 1 == 0,
      "Missing color temperature status")
    device:emit_event(values[1] and capabilities.switch.switch.on() or capabilities.switch.switch.off())
    -- Brightness is the retained dim level, including when the lamp is off.
    device:emit_event(capabilities.switchLevel.level(values[2]))
    device:emit_event(capabilities.colorTemperature.colorTemperature(values[3]))
    device:set_field("communication_failures", 0)
    device:online()
  end)
end

local function cancel_timer(device, field)
  local timer = device:get_field(field)
  if timer then
    device.thread:cancel_timer(timer)
    device:set_field(field, nil)
  end
end

local function read_back(device)
  poll(device)
  cancel_timer(device, "refresh_timer")
  device:set_field("refresh_timer", device.thread:call_with_delay(1, function()
    device:set_field("refresh_timer", nil)
    poll(device)
  end, "Light Bar command readback"))
end

local function set_power(device, value)
  if perform(device, "power command", function(ip, token)
    miot.set(device, ip, token, 2, 1, value)
  end) then read_back(device) end
end

local function set_level(_, device, command)
  local level = integer(command.args.level, 0, 100)
  if level == 0 then
    set_power(device, false)
    return
  end
  local power_applied = false
  local ok = perform(device, "brightness command", function(ip, token)
    -- Firmware 2.1.7_0020 restores saved dim/CT values on power-on, so order matters.
    miot.set(device, ip, token, 2, 1, true)
    power_applied = true
    miot.set(device, ip, token, 2, 2, level)
  end)
  if ok or power_applied then read_back(device) end
end

local function set_temperature(_, device, command)
  local temperature = integer(command.args.temperature, 2700, 6500)
  local power_applied = false
  local ok = perform(device, "color temperature command", function(ip, token)
    miot.set(device, ip, token, 2, 1, true)
    power_applied = true
    miot.set(device, ip, token, 2, 3, temperature)
  end)
  if ok or power_applied then read_back(device) end
end

local function stop(device)
  cancel_timer(device, "polling_timer")
  cancel_timer(device, "refresh_timer")
end

local function start(device)
  stop(device)
  miot.clear(device)
  device:set_field("communication_failures", 0)
  if not config(device) then
    device:offline()
    return
  end
  local interval = integer(tonumber(device.preferences.pollingInterval) or 60, 10, 300)
  device:set_field("polling_timer", device.thread:call_on_schedule(interval, function()
    poll(device)
  end, "Light Bar polling"))
  poll(device)
end

local function added(_, device)
  device:emit_event(capabilities.colorTemperature.colorTemperatureRange({
    value = { minimum = 2700, maximum = 6500 }
  }))
end

local function info_changed(driver, device, _, args)
  local old = args and args.old_st_store and args.old_st_store.preferences
  if not old then return end
  local new = device.preferences
  if old.createDev ~= true and new.createDev == true then
    discovery.create_device(driver)
  end
  if old.ipAddress ~= new.ipAddress or old.token ~= new.token
    or old.pollingInterval ~= new.pollingInterval then
    start(device)
  end
end

local driver = Driver("miot-yeelink-light-lamp22", {
  discovery = discovery.handle_discovery,
  supported_capabilities = {
    capabilities.switch, capabilities.switchLevel, capabilities.colorTemperature, capabilities.refresh
  },
  lifecycle_handlers = {
    added = added,
    init = function(_, device) start(device) end,
    removed = function(_, device) stop(device) end,
    infoChanged = info_changed
  },
  capability_handlers = {
    [capabilities.switch.ID] = {
      [capabilities.switch.commands.on.NAME] = function(_, device) set_power(device, true) end,
      [capabilities.switch.commands.off.NAME] = function(_, device) set_power(device, false) end
    },
    [capabilities.switchLevel.ID] = {
      [capabilities.switchLevel.commands.setLevel.NAME] = set_level
    },
    [capabilities.colorTemperature.ID] = {
      [capabilities.colorTemperature.commands.setColorTemperature.NAME] = set_temperature
    },
    [capabilities.refresh.ID] = {
      [capabilities.refresh.commands.refresh.NAME] = function(_, device) poll(device) end
    }
  }
})

driver:run()
