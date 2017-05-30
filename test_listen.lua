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

print("\n== Receive Lua Example Message ==")
print(default and '\n== Default ==\n' or '\n== LuaJIT ==\n')

local channel, data
while type(data)~='string' do
  local pkt, address, port = assert(transport:recv())
  print("\nPacket Size", #pkt, address, port)
  local frag
  channel, data, frag = assert(packet.assemble(pkt, #pkt, packet.gen_id(address, port)))
  print("\nChannel", channel)
  if type(frag)=='table' then
    print('======================')
    print(data, "packets remaining")
    for k,v in pairs(frag) do print(k, v) end
    print('======================')
  end
end

local obj = assert(t.decode(data))

if lcmtype=='muldim_array_t' then
  print("\nDebug multidim table")
  for i,v in pairs(obj) do
    print(i,v)
    if type(v)=='table' then
      for ii,vv in pairs(v) do
        print(ii,vv)
        if type(vv)=='table' then
          for iii,vvv in pairs(vv) do
            print(iii,vvv)
            if type(vvv)=='table' then
              for iiii,vvvv in pairs(vvv) do
                print(iiii,vvvv)
              end
            end
          end
        end
      end
    end
  end
else
  for k,v in pairs(obj) do
    print(k, type(v))
  end
end
