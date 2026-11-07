local discovery = {}
local sequence = 0

function discovery.create_device(driver)
  sequence = sequence + 1
  return driver:try_create_device({
    type = "LAN",
    device_network_id = string.format("miot-yeelink-lamp22-%d-%d", os.time(), sequence),
    label = "Mi Smart Computer Monitor Light Bar 1S",
    profile = "yeelink-light-lamp22",
    manufacturer = "Yeelink",
    model = "yeelink.light.lamp22",
    vendor_provided_label = "Mi Smart Computer Monitor Light Bar 1S"
  })
end

function discovery.handle_discovery(driver)
  if #driver:get_devices() == 0 then
    discovery.create_device(driver)
  end
end

return discovery
