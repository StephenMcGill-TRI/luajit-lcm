#!/usr/bin/env luajit

-- Usage: luajit  test_codec.lua [typename] [0]
-- 0: Default lua LCM implementation

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


local e = assert(m:encode())
print(string.format("Fingerprint: 0x%02x%02x%02x%02x%02x%02x%02x%02x", e:byte(1, 8)))
print("Number of Bytes:", #e)
for i=1,#e,8 do
  print(string.format("%3d %3d:", i,i+8-1), e:byte(i,i+8-1))
end
print("Decode itself")
local obj = assert(t.decode(e))

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
end
