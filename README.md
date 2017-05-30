# luajit-lcm
LuaJIT interface to the [Lightweight Communications and Marshalling](http://lcm-proj.github.io/) system

## Installation

The [ludent](https://github.com/lipp/ludent) formatter is optional for formatting `lcm-gen.lua` outputs.

```sh
luarocks install https://raw.githubusercontent.com/lipp/ludent/master/ludent-scm-1.rockspec
```

To install the library:

```sh
luarocks make
```

## Testing

Please download the [example LCM types folder](https://github.com/lcm-proj/lcm/tree/master/examples/types) as `types/` in the root directory of this repository before running the tests.
