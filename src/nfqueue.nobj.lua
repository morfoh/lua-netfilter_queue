-- Copyright (c) 2012 by Christian Wiese <chris@opensde.org>
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.

basetype "nfgenmsg *"		"lightuserdata" "NULL"
basetype "useconds_t"		"integer" "0"

-- typedefs
local typedefs = [[
typedef struct nlif_handle nlif_handle;

typedef struct nfq_handle nfq_handle;
typedef struct nfq_q_handle nfq_queue;
typedef struct nfgenmsg nfgenmsg;
typedef struct nfq_data nfq_data;
typedef struct nfqnl_msg_packet_hw nfqnl_msg_packet_hw;
]]
c_source "typedefs" (typedefs)
-- pass extra C type info to FFI.
ffi_cdef (typedefs)

export_definitions {
-- address families
"AF_UNSPEC",
"AF_UNIX",
"AF_INET",
"AF_INET6",
"AF_IPX",
"AF_NETLINK",
"AF_PACKET",

-- copy packet modes
"NFQNL_COPY_NONE",
"NFQNL_COPY_META",
"NFQNL_COPY_PACKET",

-- netfilter responses from hook functions
-- defined in <linux/netfilter.h>
"NF_DROP",
"NF_ACCEPT",
"NF_STOLEN",
"NF_QUEUE",
"NF_REPEAT",
"NF_STOP",
"NF_MAX_VERDICT",
}

local IFNAMSIZ = 64

--
-- nfq handle
--
object "nfq_handle" {
	--
	-- Library setup
	--

	-- open a nfqueue handler
	constructor {
		c_call "nfq_handle *" "nfq_open" {}
	},

	-- close a nfqueue handler
	destructor "close" {
		c_method_call "int" "nfq_close" {}
	},

	-- bind a nfqueue handler to a given protocol family
	method "bind_pf" {
		c_method_call "int" "nfq_bind_pf" { "uint16_t", "pf" }
	},

	-- unbind nfqueue handler from a protocol family
	method "unbind_pf" {
		c_method_call "int" "nfq_unbind_pf" { "uint16_t", "pf" }
	},

	--
	-- Helper
	--

	-- get the file descriptor associated with the nfqueue handler
	method "fd" {
		c_method_call "int" "nfq_fd" {}
	},

	-- handle a packet received from the nfqueue subsystem
	method "handle_packet" {
		var_out { "int", "rc" },
		c_source [[
#define BUF_LEN 4096
  int fd = nfq_fd(${this});
  int rv;
  char buf[BUF_LEN];

  rv = recv(fd, buf, sizeof(buf), 0);
  if (rv >= 0) {
    ${rc} = nfq_handle_packet(${this}, buf, rv);
  }
		]],
	},
}

-- nfq callback type
callback_type "NFQCallback" "int"
	{ "nfq_queue *", "qh", "nfgenmsg *", "nfmsg", "nfq_data *", "nfad", "void *", "%data" }

--
-- nfqueue queue handle
--
object "nfq_queue" {
	--
	-- Queue handling
	--

	-- create a new queue handle and return it
	constructor {
		callback { "NFQCallback", "func", "func_data", owner = "this",
			-- code to run if Lua callback function throws an error.
			c_source[[${ret} = -1;]],
			ffi_source[[${ret} = -1;]],
		},
		c_call "nfq_queue *" "nfq_create_queue" {
			"nfq_handle *", "handle<1",
			"uint16_t", "num<2",
			"NFQCallback", "func<3",
			"void *", "func_data<4"
		},
	},

	-- destroy a queue handle
	destructor "destroy_queue" {
		c_method_call "err_rc" "nfq_destroy_queue" {}
	},

	-- set the amount of packet data that nfqueue copies to userspace
	method "set_mode" {
		c_method_call "err_rc" "nfq_set_mode" { "uint8_t", "mode", "uint32_t", "range" }
	},

	-- set kernel queue maximum length parameter
	method "set_queue_maxlen" {
		c_method_call "err_rc" "nfq_set_queue_maxlen" { "uint32_t", "queuelen" }
	},

	-- issue a verdict on a packet
	method "set_verdict" {
		var_in { "uint32_t", "id"},
		var_in { "uint32_t", "verdict"},
		var_in {"const unsigned char *", "buf?"},
		c_method_call "err_rc" "nfq_set_verdict" {
			"uint32_t", "id", "uint32_t", "verdict",
			"uint32_t", "#buf", "const unsigned char *", "buf",
		},
	},

	-- issue a verdict on a packet and set a mark
	method "set_verdict2" {
		var_in { "uint32_t", "id"},
		var_in { "uint32_t", "verdict"},
		var_in { "uint32_t", "mark"},
		var_in {"const unsigned char *", "buf?"},
		c_method_call "err_rc" "nfq_set_verdict2" {
			"uint32_t", "id", "uint32_t", "verdict", "uint32_t", "mark",
			"uint32_t", "#buf", "const unsigned char *", "buf",
		},
	},
}

--
-- nfq_data
--
object "nfq_data" {
	--
	-- Message parsing functions
	--

	-- return the metaheader that wraps the packet
	method "get_msg_packet_hdr" {
		var_out { "uint32_t", "packet_id" },
		var_out { "uint16_t", "hw_protocol" },
		var_out { "uint8_t", "hook" },
		c_source "pre_src" [[
  struct nfqnl_msg_packet_hdr *ph;
		]],
		c_source [[
  ph = nfq_get_msg_packet_hdr(this);

  /* return nil when there is no packet header */
  if (!ph) {
	lua_pushnil(L);
	return 1;
  }

  /* return the package header values */
  ${packet_id} = ntohl(ph->packet_id);
  ${hw_protocol} = ntohs(ph->hw_protocol);
  ${hook} = ph->hook;
		]],
	},

	-- get the packet mark
	method "get_nfmark" {
		c_method_call "uint32_t" "nfq_get_nfmark" {}
	},

	-- get the packet timestamp
	method "get_timestamp" {
		var_out { "time_t", "tv_sec" },
		var_out { "useconds_t", "tv_usec" },
		c_source "pre_src" [[
  int rc;
  struct timeval tv;
		]],
		c_source [[
  rc = nfq_get_timestamp(this, &tv);

  /* return nil on failure */
  if (rc == -1) {
	lua_pushnil(L);
	return 1;
  }
  ${tv_sec} = tv.tv_sec;
  ${tv_usec} = tv.tv_usec;
		]],
	},

	-- get the interface that the packet was received through
	method "get_indev" {
		c_method_call "uint32_t" "nfq_get_indev" {}
	},

	-- get the name of the interface the packet was received through
	method "get_indev_name" {
		var_out{ "char *", "name", has_length = false, need_buffer = IFNAMSIZ },
		c_call "err_rc" "nfq_get_indev_name" { "nlif_handle *", "handle", "nfq_data *", "this", "char *", "name"},
	},

	-- get the physical interface that the packet was received
	method "get_physindev" {
		c_method_call "uint32_t" "nfq_get_physindev" {}
	},

	-- get the name of the physical interface the packet was received through
	method "get_physindev_name" {
		var_out{ "char *", "name", has_length = false, need_buffer = IFNAMSIZ },
		c_call "err_rc" "nfq_get_physindev_name" { "nlif_handle *", "handle", "nfq_data *", "this", "char *", "name"},
	},

	-- gets the interface that the packet will be routed out
	method "get_outdev" {
		c_method_call "uint32_t" "nfq_get_outdev" {}
	},

	-- get the name of the physical interface the packet will be sent to
	method "get_outdev_name" {
		var_out{ "char *", "name", has_length = false, need_buffer = IFNAMSIZ },
		c_call "err_rc" "nfq_get_outdev_name" { "nlif_handle *", "handle", "nfq_data *", "this", "char *", "name"},
	},

	-- get the physical interface that the packet output
	method "get_physoutdev" {
		c_method_call "uint32_t" "nfq_get_physoutdev" {}
	},

	-- get the name of the interface the packet will be sent to
	method "get_physoutdev_name" {
		var_out{ "char *", "name", has_length = false, need_buffer = IFNAMSIZ },
		c_call "err_rc" "nfq_get_physoutdev_name" { "nlif_handle *", "handle", "nfq_data *", "this", "char *", "name"},
	},
}

--
-- nfqnl_msg_packet_hw
--
object "nfqnl_msg_packet_hw" {
}
