-- Simple LCM module
local lib = {}
local dgram = require'dgram'
local lcmpacket = require'lcm-packet'
local LCM_ADDRESS0, LCM_PORT0 = "239.255.76.67", 7667

-- Update this LCM channel
local function update(self)
	local pkts, err = self.lcm_transport:recvm()
  if not pkts then return pkts, err end
  local objs = {}
  for i, pkt in ipairs(pkts) do
    local str, address, port = unpack(pkt)
    -- print(type(str), type(address), type(port))
    local id = port and lcmpacket.gen_id(address, port)
    local channel, data = lcmpacket.assemble(str, #str, id)
    -- Run the callback
    local fn = self.callbacks[channel]
    if fn then
      local msg = type(data)=='string' and self.decoders[channel](data)
      if msg then fn(msg) end
    end
  end
end

-- Add a callback for a channel
local function register(self, channel, lcm_type, fn)
  if type(fn)~='function' then
    return false, "Callback is not a function"
  elseif type(channel)~='string' then
    return false, "Channel is not a string"
  elseif type(lcm_type)~='table' then
    return false, "Bad LCM type"
  elseif type(lcm_type.decode)~='function' then
    return false, "Bad decoder"
  end
  self.callbacks[channel] = fn
  self.decoders[channel] = lcm_type.decode
  return true
end

local function send(channel, msg)
  local enc = msg:encode()
  local frag = lcmpacket.fragment(channel, enc)
  if type(frag)=='table' then
    for i, p in ipairs(frag) do lcm_transport:send(p) end
  elseif type(frag)=='string' then
    self.lcm_transport:send(frag)
  end
end

function lib.init(_LCM_ADDRESS, _LCM_PORT)
  local LCM_ADDRESS = _LCM_ADDRESS or LCM_ADDRESS0
  local LCM_PORT = _LCM_PORT or LCM_PORT0
  local lcm_transport, err = dgram.init_mc(LCM_ADDRESS, LCM_PORT)
  -- local lcm_transport, err = dgram.new_multicast(LCM_ADDRESS, LCM_PORT)
  if err then return false, err end
  return {
    lcm_transport = lcm_transport,
    update = update,
    callbacks = {},
    decoders = {},
    register = register,
    fd = lcm_transport.recv_fd,
    send = send
  }
end

return lib
