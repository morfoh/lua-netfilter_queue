-- simple test similiar to nfqnl_test.c provided by the netfilter project
-- http://netfilter.org/projects/libnetfilter_queue/doxygen/nfqnl__test_8c_source.html
--
-- setup to handle all incoming and outgoing ICMP packets
-- iptables -A INPUT --protocol icmp -j NFQUEUE --queue-num 0
-- iptables -A OUTPUT --protocol icmp -j NFQUEUE --queue-num 0
--

local nfq = require"netfilter_queue"

-- for k,v in pairs(nfq) do print(k,v) end

local function print_pkt(packet)
	-- get package header
	local id, hw_protocol, hook = packet:get_msg_packet_hdr()

	-- print packet id, hw_protocol and hook
	if id then
		io.write("id="..id)
	end
	if hw_protocol then
		io.write(" hw_protocol="..hw_protocol)
	end
	if hook then
		io.write(" hook="..hook)
	end

	-- print timestamp
	local tssec, tsusec = packet:get_timestamp() 
	if tssec and tsusec then
		io.write(" timestamp="..tssec.."."..tsusec)
	end

	-- print nfmark
	local mark = packet:get_nfmark()
	if mark then
		io.write(" mark="..mark)
	end

	-- print device infos
	local ifi

	ifi = packet:get_indev()
	if ifi then
		io.write(" indev="..ifi)
	end

	ifi = packet:get_outdev()
	if ifi then
		io.write(" outdev="..ifi)
	end

	ifi = packet:get_physindev()
	if ifi then
		io.write(" physindev="..ifi)
	end

	ifi = packet:get_physoutdev()
	if ifi then
		io.write(" physoutdev="..ifi)
	end

	io.write("\n")

	-- return the packet id
	return id
end

-- callback function
local function cb(qh, nfmsg, nfad, data)
	-- print("nfq_callback():", qh, nfmsg, nfad, data)
	local id = print_pkt(nfad)
	return qh:set_verdict(id, nfq.NF_ACCEPT)
end


local h = nfq.nfq_handle();
print("nfq_handle:", h)

print("nfq_unbind:",h:unbind_pf(nfq.AF_INET))
print("nflog_bind:", h:bind_pf(nfq.AF_INET))

local qh = nfq.nfq_queue(h, 0, cb)
print("nfq_queue:", qh)
print(nfq.NFQNL_COPY_PACKET)

--print("qh:set_mode:",qh:set_mode(nfq.NFQNL_COPY_PACKET, 0xffff))
print("qh:set_mode:",qh:set_mode(1, 0xffff))

local fd = h:fd()
print("fd = ", fd)

-- main loop
---[[
while true do
 -- local rc = h:handle_packet()
 h:handle_packet()
end
--]]

print("destroy_queue:", qh:destroy_queue())

-- normally, applications SHOULD NOT issue this command, since
-- it detaches other programs/sockets from AF_INET, too!
--
-- print("nfq_unbind:",h:unbind_pf(nfq.AF_INET))

print("nfq_close:", h:close())

