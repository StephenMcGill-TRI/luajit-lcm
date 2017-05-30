package = "luajit-lcm"
version = "0.1-0"
source = {
  url = "git://github.com/StephenMcGill-TRI/luajit-lcm.git"
}
description = {
  summary = "LCM data structures and packet generation",
  detailed = [[
    lcm-packet provides a layer for assembling and fragmenting packets using the LCM protocol in pure LuaJIT.
    lcm-gen provides data structure generation for the LCM protocol in pure LuaJIT with no dependencies.
    ]],
  homepage = "https://github.com/StephenMcGill-TRI/luajit-lcm",
  maintainer = "Stephen McGill <stephen.mcgill@tri.global>",
  license = "MIT"
}
dependencies = {
  "lua >= 5.1",
}
build = {
  type = "builtin",

  modules = {
    ["lcm"] = "lcm.lua",
    ["lcm-packet"] = "lcm-packet.lua",
  },
  install = {
    bin = {
      ["lcm-gen.lua"] = "lcm-gen.lua",
    }
  }
}
