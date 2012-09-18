#!/usr/bin/env lua

package	= 'lua-netfilter_queue'
version	= 'scm-0'
source	= {
	url	= 'https://github.com/morfoh/lua-netfilter_queue'
}
description	= {
	summary	= "Lua bindings for libnetfilter_queue.",
	detailed	= '',
	homepage	= 'https://github.com/morfoh/lua-netfilter_queue',
	license	= 'MIT',
	maintainer = "Christian Wiese",
}
dependencies = {
	'lua >= 5.1',
}
external_dependencies = {
	NETFILTER_QUEUE = {
		header = "libnetfilter_queue/libnetfilter_queue.h",
		library = "netfilter_queue",
	}
}
build	= {
	type = "builtin",
	modules = {
		netfilter_queue = {
			sources = { "src/pre_generated-netfilter_queue.nobj.c" },
			libraries = { "netfilter_queue" },
		}
	}
}
