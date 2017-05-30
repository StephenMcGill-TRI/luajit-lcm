local ffi = require'ffi'
local C = ffi.C

local packet = {}

-- Packet reassembly
local MAGIC_LCM2 = 0x4c433032
local MAGIC_LCM3 = 0x4c433033

--[[
// Disable long packet reception by setting NUM BUFFERS to zero.
// Total memory allocated is roughly:
//
// NUM_BUFFERS*(MAX_PACKET_SIZE + MAX_FRAGMENTS + CHANNEL_LENGTH) + PUBLISH_BUFFER_SIZE
//
// Note that for full LCM compatibility, CHANNEL_LENGTH must be 256.
//
--]]
local LCM3_NUM_BUFFERS = 4
local LCM3_MAX_PACKET_SIZE = 300000
local LCM3_MAX_FRAGMENTS = 256
local LCM_MAX_CHANNEL_LENGTH = 256

--[[
// LCMLite will allocate a single buffer of the size below for
// publishing messages. The LCM3 fragmentation option will be used to
// send messages larger than this.
--]]
--[[
-- for osx in the LCM library
40:#define LCM_SHORT_MESSAGE_MAX_SIZE 1435
41:#define LCM_FRAGMENT_MAX_PAYLOAD 1423
--]]
-- In lcm-lite
local MAXIMUM_HEADER_LENGTH = 300
local LCM_PUBLISH_BUFFER_SIZE = 8192

-- MTU limited if using on, e.g., a wireless link
local LCM_PUBLISH_BUFFER_SIZE = 1435

-- Max it out...
local LCM_PUBLISH_BUFFER_SIZE = 16384

ffi.cdef[[
uint32_t ntohl(uint32_t netlong);
uint16_t ntohs(uint16_t netshort);
uint32_t htonl(uint32_t hostlong);
uint32_t htons(uint16_t hostlong);
]]

-- TODO: The buffers should not be global, they should be allocated per packet instance
--local fragment_buffers = ffi.new('fragment_buffer[?]', LCM3_NUM_BUFFERS)
local fragment_buffers = {}
local last_fragment_count = 0

local function encode_u32(buf, num)
  -- Try to just use the built-in...
  -- NOTE: this may not work on embedded systems, however
  ffi.cast("uint32_t*", buf)[0] = C.htonl(num)
end

local function decode_u32(buf)
  -- Try to just use the built-in...
  -- NOTE: this may not work on embedded systems, however
  return C.ntohl(ffi.cast('uint32_t*', buf)[0])
end

local function encode_u16(buf, num)
  -- Try to just use the built-in...
  -- NOTE: this may not work on embedded systems, however
  ffi.cast("uint16_t*", buf)[0] = C.htons(num)
end

local function decode_u16(buf)
  -- Try to just use the built-in...
  -- NOTE: this may not work on embedded systems, however
  return C.ntohs(ffi.cast('uint16_t*', buf)[0])
end

local function assemble2(buf, buf_len, from_addr)
  local buf_pos = 4
  local msg_seq = decode_u32(buf + buf_pos)
  buf_pos = buf_pos + 4
  -- copy out zero-terminated string holding the channel #.
  local channel = ffi.new('uint8_t[?]', LCM_MAX_CHANNEL_LENGTH)
  local channel_len = 0

  while buf[buf_pos] ~= 0 do
    -- Test malformed packet.
    if (buf_pos >= buf_len) or (channel_len >= LCM_MAX_CHANNEL_LENGTH) then
      return false, "Malformed channel name"
    end
    channel[channel_len] = buf[buf_pos]
    buf_pos = buf_pos + 1
    channel_len = channel_len + 1
  end
  channel[channel_len] = 0
  buf_pos = buf_pos + 1 -- skip the zero.

  -- Return the Channel and Payload
  return ffi.string(channel), ffi.string(buf + buf_pos, buf_len - buf_pos)
end

local function assemble3(buf, buf_len, from_addr)
  local buf_pos = 4 -- already started...
  local msg_seq = decode_u32(buf + buf_pos)
  buf_pos = buf_pos + 4
  local msg_size = decode_u32(buf + buf_pos)
  buf_pos = buf_pos + 4
  local fragment_offset = decode_u32(buf + buf_pos)
  buf_pos = buf_pos + 4
  local fragment_id = decode_u16(buf + buf_pos)
  buf_pos = buf_pos + 2
  local fragments_in_msg = decode_u16(buf + buf_pos)
  buf_pos = buf_pos + 2

  -- TODO: Ensure >=0
  local payload_len = buf_len - buf_pos

  if fragments_in_msg > LCM3_MAX_FRAGMENTS then
    return false, "LCM3_MAX_FRAGMENTS breached: "..fragments_in_msg
  end

  if fragment_id >= fragments_in_msg then
    return false, string.format("Invalid fragment ID %d/%d", fragment_id, fragments_in_msg)
  end

  if fragment_offset + payload_len > msg_size then
    return false, string.format("Invalid fragment size %d + %d = %d > %d", fragment_offset, tonumber(payload_len), tonumber(fragment_offset + payload_len), msg_size)
  end

  -- Search for fragment
  local fbuf
  for i, f in ipairs(fragment_buffers) do
    if f.msg_seq == msg_seq and f.from_addr == from_addr then
      fbuf = f
      break
    end
  end

  -- We only do ejection here, in case there are redundant packets sent over the wire,
  -- which should not create new buffers after the packet was finished...
  if not fbuf then

    -- Not found, so create a new buffer if there is room
    -- NOTE: This is unecessary if we init the fragment buffers properly in self
    if #fragment_buffers < LCM3_NUM_BUFFERS then
      fbuf = {}
      table.insert(fragment_buffers, fbuf)
    else
      local max_age = -1
      for i, f in ipairs(fragment_buffers) do
        if f.fragments_remaining==0 then
          fbuf = f
          break
        else
          -- Find the oldest packet
          local age = last_fragment_count - f.last_fragment_count
          if age > max_age then
            max_age = age
            fbuf = f
          end
        end
      end
    end
    -- Should not get here...
    if not fbuf then return false, "Fragment not assigned" end

    -- Initialize the buffer
    --print("INIT BUFFER", msg_seq)
    fbuf.from_addr = from_addr
    fbuf.msg_seq = msg_seq
    fbuf.buf = ffi.new('uint8_t[?]', msg_size)
    fbuf.frag_received = {} -- just accumulate the received packets
    fbuf.fragments_remaining = fragments_in_msg
  end

  -- Save the fragment counters as a proxy for timestamp ages
  fbuf.last_fragment_count = last_fragment_count
  last_fragment_count = last_fragment_count + 1

  if fragment_id == 0 then
    -- this fragment contains the channel name plus data
    -- Safely find the name (In case no null termination...)
    local channel_len = 0
    while buf[buf_pos] ~= 0 do
      if buf_pos >= buf_len or channel_len >= LCM_MAX_CHANNEL_LENGTH then
        return false, "Bad name"
      end
      channel_len = channel_len + 1
      buf_pos = buf_pos + 1
    end
    -- We know for certain it is null terminated
    fbuf.channel = ffi.string(buf + buf_pos - channel_len)
    -- Skip the null termination in the buffer
    buf_pos = buf_pos + 1
  end

  -- Copy the payload fragment into the buffer
  if buf_pos < buf_len then
    ffi.copy(fbuf.buf + fragment_offset, buf + buf_pos, buf_len - buf_pos)
  end

  -- Accounting update in case we have not seen this fragment before
  if not fbuf.frag_received[fragment_id+1] then
    fbuf.frag_received[fragment_id+1] = true
    fbuf.fragments_remaining = fbuf.fragments_remaining - 1
    -- Debug
    --[[
    local pkts={}
    for i=1,fragments_in_msg do
      pkts[i] = fbuf.frag_received[i] and 'X' or '-'
    end
    print("Packets:", table.concat(pkts))
    --]]

    -- Check if we are done assembling this fragment
    if fbuf.fragments_remaining == 0 then
    --if #fbuf.frag_received == fragments_in_msg then
      --print("Delivering...")
      return fbuf.channel, ffi.string(fbuf.buf, msg_size)
    elseif #fbuf.frag_received > fragments_in_msg then
      return false, "Extra packets"
    end
  end

  return fbuf.channel, fbuf.fragments_remaining, fbuf
end

-------------------
-- Assembly area --
-------------------
-- Buffer is a uint8_t*
function packet.assemble(buffer, buf_len, msgid)
  if not buffer then return false, "bad input" end
  if buf_len < 4 then return false, "Header too small" end
  local buf = ffi.cast('uint8_t*', buffer)
  local magic = decode_u32(buf)
  return (magic==MAGIC_LCM2 and assemble2 or assemble3)(buf, buf_len, msgid)
end

function packet.get_nfragments(buffer, buf_len)
  if buf_len < 4 then return false, "Header too small" end
  local buf = ffi.cast('uint8_t*', buffer)
  return decode_u32(buf)==MAGIC_LCM2 and 1 or decode_u16(buf + 18)
end

------------------------
-- Fragmentation area --
------------------------

-- Channel is a string
-- TODO: Message is string or void*
-- TODO: Have a pre-existing buffer for message sending...
-- Smaller buffer creation
local function frag2(channel, message, msg_len, msg_seq)
  -- Assemble non-fragmented message
  local buf_pos = 0
  local buf = ffi.new('uint8_t[?]', LCM_PUBLISH_BUFFER_SIZE)
  local msg = ffi.cast("uint8_t*", message)
  -- Set the header identifier
  encode_u32(buf + buf_pos, MAGIC_LCM2)
  buf_pos = buf_pos + 4
  -- TODO: Track the message sequence
  encode_u32(buf + buf_pos, msg_seq)
  buf_pos = buf_pos + 4
  -- copy channel
  ffi.copy(buf + buf_pos, channel)
  -- Plus the null terminator
  buf_pos = buf_pos + #channel + 1

  ffi.copy(buf + buf_pos, msg, msg_len);
  buf_pos = buf_pos + msg_len

  return ffi.string(buf, buf_pos)
end

-- TODO: Make this coroutine based
local function frag3(channel, message, msg_len, msg_seq)
  --print('sending', msg_len)
  local fragment_offset = 0
  --local max_fragment_size = LCM_PUBLISH_BUFFER_SIZE - MAXIMUM_HEADER_LENGTH
  -- 20 is the header length; channel is the remaining bit
  local max_fragment_size = LCM_PUBLISH_BUFFER_SIZE - 20 - #channel - 1
  local fragment_id = 0
  local fragments_in_msg = math.floor((msg_len + max_fragment_size - 1) / max_fragment_size)
  local msg = ffi.cast("uint8_t*", message)
  -- Table-based for now...
  local fragments = {}
  local buf = ffi.new('uint8_t[?]', LCM_PUBLISH_BUFFER_SIZE)
  -- Go through the message
  while fragment_offset < msg_len do
    local buf_pos = 0
    -- Push in the header information
    encode_u32(buf + buf_pos, MAGIC_LCM3)
    buf_pos = buf_pos + 4
    encode_u32(buf + buf_pos, msg_seq)
    buf_pos = buf_pos + 4
    encode_u32(buf + buf_pos, msg_len)
    buf_pos = buf_pos + 4
    encode_u32(buf + buf_pos, fragment_offset)
    buf_pos = buf_pos + 4
    encode_u16(buf + buf_pos, fragment_id)
    buf_pos = buf_pos + 2
    encode_u16(buf + buf_pos, fragments_in_msg)
    buf_pos = buf_pos + 2
    if fragment_id==0 then
      -- Copy the channel name
      ffi.copy(buf + buf_pos, channel)
      -- Plus the null terminator
      buf_pos = buf_pos + #channel + 1
    end
    -- Fragment management for _this_ fragment
    local frag_sz = math.min(msg_len - fragment_offset, max_fragment_size)
    --print('frag_sz', frag_sz)
    ffi.copy(buf + buf_pos, msg + fragment_offset, frag_sz)
    buf_pos = buf_pos + frag_sz
    table.insert(fragments, ffi.string(buf, buf_pos))
    -- Accounting
    fragment_offset = fragment_offset + frag_sz
    fragment_id = fragment_id + 1
  end
  return fragments
end

function packet.fragment(channel, message, msg_seq)
  local msg_sz = #message
  if (msg_sz < LCM_PUBLISH_BUFFER_SIZE - MAXIMUM_HEADER_LENGTH) then
    return frag2(channel, message, msg_sz, msg_seq or 1)
  else
    return frag3(channel, message, msg_sz, msg_seq or 1)
  end
end

function packet.gen_id(address, port)
  return bit.bor(address, ffi.cast('uint64_t', bit.lshift(port, 32)))
end

return packet
