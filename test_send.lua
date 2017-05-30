#!/usr/bin/env luajit

-- Usage: luajit test_send.lua [typename] [0]
-- 0: Default lua LCM implementation
-- In order to run the default encoder, ensure you run:
-- lcm-gen -l types/*.lcm

-- NOTES:
-- Testing, Receiver
-- mcfirst  239.255.76.67 7667
-- Testing, sender or receiver
-- nc -vzu 239.255.76.67 7667
-- Ensure the TTL is set properly for your configuration
-- export LCM_DEFAULT_URL=udpm://239.255.76.67:7667?ttl=1

local skt = require'skt'
local packet = require'packet'

local ADDRESS, PORT = "239.255.76.67", 7667
local transport = assert(skt.init_mc(ADDRESS, PORT))

local lcmtype = 'example_t'
local default = false
if tonumber(arg[1]) then
  default = true
elseif arg[1] then
  lcmtype = arg[1]
end

if tonumber(arg[2]) and tonumber(arg[2])==0 then
  default = true
end

if default then
  -- Default generation from lcm-gen
  package.path = package.path .. ';exlcm0/?.lua'
else
  package.path = package.path .. ';exlcm/?.lua'
end

local t = require(lcmtype)

print("\n== Send Lua Example Message ==")
print(default and '\n== Default ==\n' or '\n== LuaJIT ==\n')
local m = t:new()

if lcmtype=='muldim_array_t' then
  m.size_a = 2
  m.size_b = 2
  m.size_c = 2
  m.data = {}
  for i = 1, m.size_a do
    table.insert(m.data, {})
    for j = 1, m.size_b do
      table.insert(m.data[i], {})
      for k = 1, m.size_c do
        m.data[i][j][k] = i*j*k
      end
    end
  end
  m.strarray = {}
  for i = 1, 2 do
    m.strarray[i] = {}
    for j = 1, m.size_c do
      m.strarray[i][j] = "Hello"
    end
  end
elseif lcmtype=='example_t' then
  local NRANGE = 15
  m.timestamp = os.time() -- time in seconds
  m.position = {1, 2, 3}
  m.orientation = {1, 0, 0, 0}
  for i = 1, NRANGE do
    table.insert(m.ranges, i)
  end
  m.num_ranges = #m.ranges
  m.name = "example string"
  m.enabled = true
end

-- Sending
local e = assert(m:encode())

local frag = packet.fragment("EXAMPLE", e)
if type(frag)=='table' then
  for i, f in ipairs(frag) do
    print(string.format('Sending %d / %d', i, #frag))
    transport:send(f)
  end
else
  transport:send(frag)
end
