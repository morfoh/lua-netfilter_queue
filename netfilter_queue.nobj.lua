-- make generated variable nicer
set_variable_format "%s"

c_module "netfilter_queue" {

-- enable FFI bindings support.
luajit_ffi = true,

-- load NETFILTER_QUEUE shared library.
ffi_load"netfilter_queue",

sys_include "unistd.h",
sys_include "netinet/in.h",
sys_include "linux/netfilter.h",
sys_include "libnetfilter_queue/libnetfilter_queue.h",

subfiles {
"src/error.nobj.lua",
"src/nfqueue.nobj.lua",
},
}

