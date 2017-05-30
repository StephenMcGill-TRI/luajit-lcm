#!/usr/bin/env luajit

local ffi = require'ffi'
local bit = require'bit'

local ENABLE_CDATA = true

local defaults = {
  int8_t = '0',
  int16_t = '0',
  int32_t = '0',
  int64_t = ENABLE_CDATA and "ffi.new'int64_t'" or "0",
  boolean = 'false',
  float = '0.0',
  double = '0.0',
  string = '""',
  byte = '0',
}

local ffitypes = {
  int8_t = 'int8_t',
  int16_t = 'int16_t',
  int32_t = 'int32_t',
  int64_t = 'int64_t',
  boolean = 'uint8_t',
  float = 'float',
  double = 'double',
  string = 'uint8_t',
  byte = 'uint8_t',
}

local type_sz = {
  int8_t = 1,
  int16_t = 2,
  int32_t = 4,
  int64_t = 8,
  boolean = 1,
  float = 4,
  double = 8,
  byte = 1,
}

local function update_hash_number(h, c)
  assert(type(c)=='number', "Invalid hash number")
  local h1 = bit.bxor(bit.lshift(h, 8), bit.arshift(h, 55)) + c
--  print(string.format("[0x%s] -> (%c:%d) -> [0x%s]", bit.tohex(h), c, c, bit.tohex(h1)))
  return h1
end

local function update_hash_string(h, s)
  assert(type(s)=='string', "Invalid hash string")
  h = update_hash_number(h, #s)
  for i=1,#s do h = update_hash_number(h, s:byte(i)) end
  return h
end

local function emit_file_str(package, struct, comments, variables, constants)
  local tbl = {
    "local ffi = require'ffi'",
    string.format("local %s = {}", struct),
    string.format("%s.__index = %s", struct, struct),
  }

  local substructs = {}
  local substructs_set = {}
  for iv,v in pairs(variables) do
    -- Add the struct stuff for fingerprinting
    if not ffitypes[v.type] then
      table.insert(substructs, v.type)
      substructs_set[v.type] = #substructs
    end
  end
  -- Require only once, so use the has of pairs
  for s in pairs(substructs_set) do
    -- table.insert(tbl, string.format("local %s = require'%s'",s,s))
    table.insert(tbl, string.format("local %s = require'%s.%s'",s,package,s))
  end

  -- Constants
  table.insert(tbl, "-- Constants")
  for c, v in pairs(constants) do
    table.insert(tbl, string.format("%s.%s = %s",struct,c,v))
    --print(c, v)
  end

  -- Make the new pbj
  local new_obj = {
    "\n-- New Object",
    string.format("function %s:new()", struct),
    "local obj = {}"
  }
  for iv,v in pairs(variables) do

    local populate = {
      string.format("obj.%s=", v.name)
    }

    if #v.dims == 0 then
      populate[1] = populate[1]..(defaults[v.type] or v.type..":new()")
    else
      populate[1] = populate[1].."{}"
      for i, n in ipairs(v.dims) do
        if type(n)~='number' then break end
        local pop = string.format("for i%d = 1,%d do",i,n)
        table.insert(populate, pop)
        -- TODO: This is wrong...
        local pop_val = string.format("obj.%s[i%d]=", v.name, i)
        if i==#v.dims then
          pop_val = pop_val..(defaults[v.type] or v.type..":new()")
        else --if type(v.dims[i+1])=='string' then
          pop_val = pop_val.."{}"
        end
        table.insert(populate, pop_val)
      end
      for i, n in ipairs(v.dims) do
        if type(n)~='number' then break end
        table.insert(populate, "end")
      end
    end
    table.insert(new_obj, table.concat(populate,"\n"))
  end
  table.insert(new_obj, "return setmetatable(obj, self)")
  table.insert(new_obj, "end")
  table.insert(tbl, table.concat(new_obj,'\n'))
  new_obj = nil
  -- Fingerprint generation
  local fp_obj = {
    "\n-- Fingerprint generation",
  }

  -- For reference: lcm_member_dump, lcm_dimension_t, lcm_struct_has
  local LCM_CONST, LCM_VAR = 0, 1
  local h = ffi.new('uint64_t', 0x12345678) -- hash
  for iv,v in pairs(variables) do
    --print("++",iv,"++")
    -- hash the member name
    h = update_hash_string(h, v.name)
    -- hash the primitive name
    if ffitypes[v.type] then
      h = update_hash_string(h, v.type)
    end
    -- hash the dimensionality information
    h = update_hash_number(h, #v.dims)
    for id, d in ipairs(v.dims) do
      h = update_hash_number(h, type(d)=='number' and LCM_CONST or LCM_VAR)
      h = update_hash_string(h, tostring(d))
    end
  end

  -- Save the base hash
  local base_hash = h
  table.insert(fp_obj, string.format("-- Base Hash: 0x%s", bit.tohex(base_hash)) )

  if #substructs > 0 then
    local strtbl = {}
    for x in bit.tohex(base_hash):gmatch("%x%x") do
      table.insert(strtbl, '0x'..x)
    end
    local hash_bytes = table.concat(strtbl,',')

    table.insert(fp_obj, string.format("function %s.get_fingerprint(parents)", struct))
    table.insert(fp_obj, [[
    -- Copy parents until we spot ourselves
    local newparents = {}
    for _, v in ipairs(parents) do
      if v == ]]..struct..[[ then return 0x0 end
      table.insert(newparents, v)
    end]])
    -- table.insert(fp_obj, [[local tmp = ffi.new('uint8_t[8]', string.char(]]..hash_bytes..[[):reverse())
    -- local val = ffi.cast('uint64_t*', tmp)[0]
    -- local hash = val]])
    table.insert(fp_obj, string.format("local hash = 0x%sLL", bit.tohex(base_hash):upper()))
    for i,s in ipairs(substructs) do
      table.insert(fp_obj, string.format("+ %s.get_fingerprint(newparents)", s))
    end
    table.insert(fp_obj, "return require'bit'.rol(hash, 1)")
    table.insert(fp_obj, "end")
    -- Actually form the fingerprint here
    table.insert(fp_obj, struct..".fingerprint = {}")
    table.insert(fp_obj, "for v in require'bit'.tohex("..struct..".get_fingerprint({})):gmatch('%x%x') do")
    table.insert(fp_obj, "table.insert("..struct..".fingerprint, tonumber('0x'..v))")
    table.insert(fp_obj, "end")
    -- No need to reverse, with Lua constructing the string
    table.insert(fp_obj, struct..".fingerprint = string.char(unpack("..struct..".fingerprint))")
  else
    -- Single is easy
    local strtbl = {}
    local h_rot1 = bit.rol(base_hash, 1)
    for x in bit.tohex(h_rot1):gmatch("%x%x") do
      table.insert(strtbl, '0x'..x)
    end
    table.insert(fp_obj, string.format("%s.fingerprint = string.char(%s)", struct, table.concat(strtbl,',')) )

    table.insert(fp_obj, string.format("function %s.get_fingerprint(parents)", struct))
    table.insert(fp_obj, [[
      local tmp = ffi.new('uint8_t[8]', ]]..struct..[[.fingerprint:reverse())
      local val = ffi.cast('uint64_t*', tmp)[0]
      return val]])
    table.insert(fp_obj, "end")
  end
  table.insert(tbl, table.concat(fp_obj,'\n'))
  fp_obj = nil

  -- Decode
  local decode_obj = {
    "\n-- Decoder",
    string.format("function %s.decode(data, skip_fingerprint)", struct),
    [[
    if type(data)~='string' or #data==0 then
      return false, "]]..struct..[[ cannot decode "..(type(data)=='string' and #data or type(data))
    end
    local idata = skip_fingerprint and 1 or 9
    if (not skip_fingerprint) and data:sub(1,8)~=]]..struct..[[.fingerprint then
      return false, "Bad fingerprint"
    end
    local obj = setmetatable({},]]..struct..")",
  }
  -- Order of decoding
  for iv,v in pairs(variables) do
    --assert(type(type_sz[v.type])=='number', "No type size defined"..v.type)
    local ftype = ffitypes[v.type]
    local digest = {
      "\n-- Digesting "..v.name
    }
    -- TODO: Option to keep as cdata
    -- If not ftype, then it is another module
    if not ftype then
      -- TODO: Multidim for objects
      if #v.dims > 0 then
        table.insert(digest, string.format("obj.%s = {}", v.name))
        -- Only if the dims is a string...
        if type(v.dims[1])=='string' then
          table.insert(digest, string.format("for n=1, obj.%s do", v.dims[1]))
        else
          table.insert(digest, string.format("for n=1, %d do", v.dims[1]))
        end
        table.insert(digest, string.format("local o, sz = assert(%s.decode(data:sub(idata), true))", v.type))
        table.insert(digest, string.format("table.insert(obj.%s, o)", v.name))
        table.insert(digest, "idata = idata + sz")
        table.insert(digest, "end")
      else
        table.insert(digest, string.format("local o, sz = assert(%s.decode(data:sub(idata), true))", v.type))
        table.insert(digest, string.format("obj.%s = o", v.name))
        table.insert(digest, "idata = idata + sz")
      end

    elseif v.type=='string' then
      -- String
      if #v.dims > 0 then
        -- Make the sizes available for Lua to use in the loops
        local obj_dims = {}
        for i,d in ipairs(v.dims) do
          obj_dims[i] = type(d)=='string' and 'obj.'..d or d
        end
        -- Array (possibly multidim)
        -- Outer of loop definitions
        local accessors = {}
        for i, d in ipairs(obj_dims) do
          table.insert(digest, string.format("obj.%s%s = {}", v.name, table.concat(accessors)) )
          table.insert(digest, string.format("for i%d = 1, %s do", i, d))
          table.insert(accessors, string.format("[i%d]", i))
        end
        -- Inner
        table.insert(digest, "local sz = ffi.cast('uint32_t*', data:sub(idata, idata+3):reverse())[0]")
        table.insert(digest, "idata = idata + 4")
        -- We receive a null terminator from LCM always
        table.insert(digest, string.format("obj.%s%s = ffi.string(data:sub(idata, idata+sz), sz-1)", v.name, table.concat(accessors)))
        table.insert(digest, "idata = idata + sz")
        -- Close
        for i, d in ipairs(obj_dims) do table.insert(digest, "end") end
      else
        table.insert(digest, "local sz = ffi.cast('uint32_t*', data:sub(idata, idata+3):reverse())[0]")
        table.insert(digest, "idata = idata + 4")
        -- We receive a null terminator from LCM always
        table.insert(digest, string.format("obj.%s = ffi.string(data:sub(idata, idata+sz), sz-1)", v.name))
        table.insert(digest, "idata = idata + sz")
      end
    elseif v.type=='byte' and #v.dims > 0 then
      --print("BYTE ARRAY")
      -- Byte array
      -- Make the sizes available for Lua to use in the loops
      local obj_dims = {}
      for i,d in ipairs(v.dims) do
        obj_dims[i] = type(d)=='string' and 'obj.'..d or d
      end
      -- Array (possibly multidim)
      table.insert(digest, "sz = "..table.concat(obj_dims,'*'))
      table.insert(digest, string.format("obj.%s = data:sub(idata, idata+sz-1)", v.name))
      table.insert(digest, "idata = idata + sz")
    elseif #v.dims > 0 then
      table.insert(digest, string.format("obj.%s = {}", v.name))
      -- Make the sizes available for Lua to use in the loops
      local obj_dims = {}
      for i,d in ipairs(v.dims) do
        obj_dims[i] = type(d)=='string' and 'obj.'..d or d
      end
      -- Populate the Lua table with the cdata array information
      table.insert(digest,
      string.format("local substr = data:sub(idata, idata+%d*%s-1):reverse()", type_sz[v.type], table.concat(obj_dims, "*"))
      )
      table.insert(digest,
      string.format("local ptr = ffi.cast('%s*', substr )", ftype)
      )
      -- Array (possibly multidim)
      table.insert(digest, "local ibuf = 0")
      -- Outer of loop definitions
      -- NOTE: Endian reversal
      local accessors = {}
      for i, d in ipairs(obj_dims) do
        table.insert(digest, string.format("obj.%s%s = {}", v.name, table.concat(accessors)) )
        table.insert(digest, string.format("for i%d = %s, 1, -1 do", i, d))
        table.insert(accessors, string.format("[i%d]", i))
      end
      -- Inner
      -- TODO: This is wrong...
      table.insert(digest, string.format("obj.%s%s = ptr[ibuf]%s", v.name, table.concat(accessors), v.type=='boolean' and '>0' or ''))
      table.insert(digest, "ibuf = ibuf + 1")
      -- Close
      for i, d in ipairs(obj_dims) do table.insert(digest, "end") end
      table.insert(digest, "idata = idata + #substr")
    else
      -- Single element
      table.insert(digest,
      string.format("obj.%s = ffi.cast('%s*', data:sub(idata, idata+%d-1):reverse() )[0]%s",
      v.name, ftype, type_sz[v.type], v.type=='boolean' and '>0' or '')
      )
      table.insert(digest, string.format("idata = idata + %d", type_sz[v.type]) )
    end
    table.insert(decode_obj, table.concat(digest, '\n'))
  end
  table.insert(decode_obj, [[
  if skip_fingerprint or idata-1==#data then
    return obj, idata-1
  end
  return false, "Bad cursor: ]]..struct..'"')
  table.insert(decode_obj, "end")
  table.insert(tbl, table.concat(decode_obj,'\n'))
  decode_obj = nil

  -- Encode
  local encode_obj = {
    "\n-- Encoder",
    string.format("function %s:encode(skip_fingerprint)", struct),
    "local tbl = {}",
    "local n, data"
  }
  -- Fingerprint
  table.insert(encode_obj,[[
  -- Fingerprint
  if not skip_fingerprint then
    table.insert(tbl, self.fingerprint)
  end]])

  -- Variables
  for iv,v in pairs(variables) do
    table.insert(encode_obj, "\n-- Encoding "..v.name)
    local ftype = ffitypes[v.type]
    if not ftype then
      if #v.dims > 0 then
        -- Only if the dims is a string...
        if type(v.dims[1])=='string' then
          table.insert(encode_obj, string.format("for n=1, self.%s do", v.dims[1]))
        else
          table.insert(encode_obj, string.format("for n=1, %d do", v.dims[1]))
        end
        table.insert(encode_obj, string.format("local e = assert(self.%s[n]:encode(true))", v.name))
        table.insert(encode_obj, "table.insert(tbl, e)")
        table.insert(encode_obj, "end")
      else
        table.insert(encode_obj, string.format("local e = assert(self.%s:encode(true))", v.name))
        table.insert(encode_obj, "table.insert(tbl, e)")
      end
    elseif v.type=='string' then
      if #v.dims>0 then
        local obj_dims = {}
        for i,d in ipairs(v.dims) do
          obj_dims[i] = type(d)=='string' and 'self.'..d or d
        end
        -- Outer of loop definitions
        -- NOTE: Endian reversal
        local accessors = {}
        for i, d in ipairs(obj_dims) do
          table.insert(encode_obj, string.format("for i%d = 1, %s do", i, d))
          table.insert(accessors, string.format("[i%d]", i))
        end
        -- Inner
        -- TODO: This is wrong...
        table.insert(encode_obj, string.format("n = ffi.new('uint32_t[1]', #self.%s%s+1)", v.name, table.concat(accessors)))
        table.insert(encode_obj, "table.insert(tbl, ffi.string(n, 4):reverse())")
        table.insert(encode_obj, string.format("table.insert(tbl, self.%s%s)", v.name, table.concat(accessors)) )
        table.insert(encode_obj, "table.insert(tbl, '\\0')")
        -- Close
        for i, d in ipairs(obj_dims) do
          table.insert(encode_obj, "end")
        end
      else
        table.insert(encode_obj, string.format("n = ffi.new('uint32_t[1]', #self.%s+1)", v.name))
        table.insert(encode_obj, "table.insert(tbl, ffi.string(n, 4):reverse())")
        table.insert(encode_obj, string.format("table.insert(tbl, self.%s)", v.name))
        table.insert(encode_obj, "table.insert(tbl, '\\0')")
      end
      --table.insert(encode_obj, string.format("table.insert(tbl, ffi.string(ffi.cast('uint8_t*', self.%s), #self.%s))", v.name, v.name))
    elseif v.type=='byte' then
      -- We assume bytes are just strings!
      -- NOTE: No multidim support for now
      if #v.dims>2 then
        error("Only single dimension supported")
      else
        -- Just a single number or a single string
        table.insert(encode_obj, string.format("table.insert(tbl, self.%s)", v.name))
      end
      --table.insert(encode_obj, string.format("table.insert(tbl, ffi.string(ffi.cast('uint8_t*', self.%s), #self.%s))", v.name, v.name))
    elseif #v.dims>0 then
      -- TODO: Multidim arrays
      local obj_dims = {}
      for i,d in ipairs(v.dims) do
        obj_dims[i] = type(d)=='string' and 'self.'..d or d
      end
      -- Array (possibly multidim)
      table.insert(encode_obj, string.format("n = %s", table.concat(obj_dims, "*")))
      table.insert(encode_obj, string.format("data = ffi.new('%s[?]', n)", ftype))
      table.insert(encode_obj, "local ibuf = 0")
      -- Outer of loop definitions
      -- NOTE: Endian reversal
      local accessors = {}
      for i, d in ipairs(obj_dims) do
        table.insert(encode_obj, string.format("for i%d = %s, 1, -1 do", i, d))
        table.insert(accessors, string.format("[i%d]", i))
      end
      -- Inner
      -- TODO: This is wrong...
      table.insert(encode_obj, string.format("data[ibuf] = self.%s%s", v.name, table.concat(accessors)) )
      table.insert(encode_obj, "ibuf = ibuf + 1")
      -- Close
      for i, d in ipairs(obj_dims) do
        table.insert(encode_obj, "end")
      end
      -- NOTE: Endian reversal
      table.insert(encode_obj, string.format("table.insert(tbl, ffi.string(data, n*%s):reverse())", type_sz[v.type]))
    else
      table.insert(encode_obj, string.format("data = ffi.new('%s[1]', self.%s)", ftype, v.name))
      -- NOTE: Endian reversal
      table.insert(encode_obj, string.format("table.insert(tbl, ffi.string(data, %s):reverse())", type_sz[v.type]))
    end
  end-- for
  table.insert(encode_obj, "return table.concat(tbl)")
  table.insert(encode_obj, "end")
  table.insert(tbl, table.concat(encode_obj,'\n'))
  encode_obj = nil
  -- Assemble Full file
  table.insert(tbl, "return "..struct)
  return table.concat(tbl,'\n')
end

local function process(l, IS_COMMENT)
  -- If nothing on the line then return
  if not l:match"%S+" then return "BLANK" end
  -- If the line starts with a double forward slash
  local comment = l:find"%s*//"==1
  if comment then
    return "COMMENT", l:match"//(.*)"
  end
  local pkg = l:match"%s*package%s+(%S+);"
  if pkg then return "PKG", pkg end
  if l:find"%s*struct%s"==1 then
    local struct = l:match"%s*struct%s+(%S+)[{%s*]?"
    return "STRUCT", assert(struct, l)
  end
  -- Assume that the constants are defined on the same line
  if l:match("const") then
    local constants = {}
    for d,e in l:gmatch"([%w_%-]+)%s*=%s*([%.x%d%x]+)%s*[,;]" do
      -- TODO: Handle 64 bit numbers
      constants[d] = assert(tonumber(e) or tonumber(e, 16))
    end
    return "CONSTANT", constants
  end
  -- Struct variables
  if l:match("([%w_]+).*;") then
    --local typ, name, arr = l:match("([%w_]+)%s+([%w%-_]+)(%S*);%s*")
    local typ, name, arr = l:match"([%w_]+)%s+([%w%-_]+)%s*(%S*);"
    local dims = {}
    for a in arr:gmatch"([%w_%-]+)" do
      table.insert(dims, tonumber(a) or a)
    end
    return "VARIABLE",{
      type = typ,
      name = name,
      dims = dims
    }
  end
  -- Assume that these are on their own lines
  if l:find"{" then return"OPEN" end
  if l:find"}" then return"CLOSE" end
  if l:find"/\\*" then return"COMMENTOPEN", l end
  if l:find"\\*/" then return"COMMENTCLOSE", l end
  if IS_COMMENT then return"COMMENT", l end
  --
  error("UNKNOWN LINE: "..l)
end

-- Default directory of the types
local dir = arg[1] or 'types'
io.write("Directory "..dir, "\n======\n")
local fnames = {}
for fname in io.popen('ls '..dir):lines() do
  -- Check suffix
  local a,b = fname:find".lcm"
  if b==#fname then
    local fname0 = fname:sub(1,a-1)
    io.write(fname0, '\n')
    table.insert(fnames, fname0)
  end
end

local file_str = {}
for i,fname in ipairs(fnames) do
  io.write("\n\nProcessing ", fname, '\n')
  -- Process each one in kind
  local package = 'default'
  local struct
  local comments = {}
  local variables = {}
  local constants = {}
  local f = assert(io.open(dir.."/"..fname..".lcm"))
  local IS_COMMENT = false
  for l in f:lines() do
    local el, val = assert(process(l, IS_COMMENT))
    if el=="CLOSE" then break end
    if el=="CONSTANT" then
      assert(type(val)=='table')
      for name,value in pairs(val) do
        assert(type(value)=='number' or type(value)=='cdata')
        constants[name] = value
      end
    elseif el=="VARIABLE" then
      table.insert(variables, val)
    elseif el=="COMMENT" then
      table.insert(comments, val)
    elseif el=="COMMENTOPEN" then
      IS_COMMENT = true
      table.insert(comments, val)
    elseif el=="COMMENTCLOSE" then
      IS_COMMENT = false
      table.insert(comments, val)
    elseif el=="PKG" then
      package = val
    elseif el=="STRUCT" then
      --print(fname, val)
      --assert(fname==val)
      struct = val
    end
  end
  f:close()
  -- Print out the parsing results
  --[[
  print("Package", package)
  print("Constants")
  for k,v in pairs(constants) do print('\t', k, v, type(v) ) end
  print("Variables")
  for k,v in pairs(variables) do
  io.write("\t", string.format('%s=%s', k, v.type))
  if #v.dims>0 then
  io.write("[",table.concat(v.dims,"]["),"]")
  end
  io.write('\n')
  end
  --]]
  -- Emit the file
  local str = emit_file_str(package, struct, comments, variables, constants)
  file_str[string.format("%s/%s.lua",package,struct)] = str
  --print('\n')
  --io.write(str)
  package = package or 'default'
  os.execute("mkdir -p "..package)
  local out_fname = string.format("%s/%s.lua",package,struct)
  local f = assert(io.open(out_fname, 'w'))
  f:write(str)
  f:close()
  -- Correctly indent the resulting file
  --os.execute("ludent "..out_fname)
end
