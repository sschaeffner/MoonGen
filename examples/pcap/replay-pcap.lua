--- Replay a pcap file.

local mg      = require "moongen"
local device  = require "device"
local memory  = require "memory"
local stats   = require "stats"
local log     = require "log"
local pcap    = require "pcap"
local limiter = require "software-ratecontrol"

function configure(parser)
	parser:argument("edev", "Device to use for egress."):args(1):convert(tonumber)
	parser:argument("idev", "Device to use for ingress."):args(1):convert(tonumber)
	parser:argument("file", "File to replay."):args(1)
	parser:option("-s --src-mac", "Overwrite source MAC address of every sent packet"):default(''):target("srcMAC")
	parser:option("-d --dst-mac", "Overwrite destination MAC address of every sent packet"):default(''):target("dstMAC")
	parser:option("-f --fix-rate", "Fixed net data rate in Mbit per second (ignore timestamps in pcap)"):default(0):convert(tonumber):target("fixedRate")
	parser:option("-v --fix-packetrate", "Fixed net data rate in packets per second (ignore timestamps in pcap)"):default(0):convert(tonumber):target("fixedPacketRate")
	parser:option("-r --rate-multiplier", "Speed up or slow down replay, 1 = use intervals from file, default = replay as fast as possible"):default(0):convert(tonumber):target("rateMultiplier")
	parser:option("-p --packets", "Send only the number of packets specified"):default(0):convert(tonumber):target("numberOfPackets")
	parser:flag("-l --loop", "Repeat pcap file.")
	local args = parser:parse()
	return args
end

function master(args)
	local edev = device.config{port = args.edev}
	local idev = device.config{port = args.idev, dropEnable = false}
	device.waitForLinks()
	local rateLimiter
	if args.rateMultiplier > 0 and args.fixedPacketRate > 0 then
		print("-r and -v option cannot be set at the same time.")
		return
	end
	if args.rateMultiplier > 0 and args.fixedRate > 0 then
		print("-r and -f option cannot be set at the same time.")
		return
	end
	if args.rateMultiplier > 0 or args.fixedRate > 0 or args.fixedPacketRate then
		rateLimiter = limiter:new(edev:getTxQueue(0), "custom")
	end
	if args.dstMAC ~= '' then
		print("Replace dstMAC with " ..  args.dstMAC)
	end
	if args.srcMAC ~= '' then
		print("Replace srcMAC with " .. args.srcMAC)
	end
	if args.fixedPacketRate ~= 0 then
		print("Fixed packet rate " .. args.fixedPacketRate .. " pps")
	end
	dstmc = parseMacAddress(args.dstMAC, 0)
	srcmc = parseMacAddress(args.srcMAC, 0)
	mg.startTask("replay", edev:getTxQueue(0), args.file, args.loop, rateLimiter, args.rateMultiplier, args.fixedRate, args.numberOfPackets, dstmc, srcmc, args.fixedPacketRate)
	stats.startStatsTask{txDevices = {edev}, rxDevices = {idev}}
	mg.waitForTasks()
end

function replay(queue, file, loop, rateLimiter, multiplier, fixedRate, numberOfPackets, dstMAC, srcMAC, fixedPacketRate)
	local mempool = memory:createMemPool(4096)
	local bufs = mempool:bufArray()
	local pcapFile = pcap:newReader(file)
	local prev = 0
	local linkSpeed = queue.dev:getLinkStatus().speed
	while mg.running() do
		fixedRateAcc = 0
		local n = pcapFile:read(bufs)
		if n > 0 and numberOfPackets > 0 then
			if rateLimiter ~= nil then
				if prev == 0 then
					prev = bufs.array[0].udata64
				end
				for i, buf in ipairs(bufs) do
					if numberOfPackets > 0 then
						if i > n then break end
						if dstMAC ~= nil then
							local pkt = buf:getEthernetPacket()
							pkt.eth:setDst(dstMAC)
						end
						if srcMAC ~= nil then
							local pkt = buf:getEthernetPacket()
							pkt.eth:setSrc(srcMAC)
						end
						-- ts is in microseconds
						local ts = buf.udata64
						if prev > ts then
					                ts = prev
						end
						sz = buf:getSize()
						local delay = ts - prev
						delay = tonumber(delay * 10^3) / multiplier -- nanoseconds
						delay = delay / (8000 / linkSpeed) -- delay in bytes
						if fixedRate > 0 then
							delay = (sz + 4) / (fixedRate/10000)
						end
						if fixedPacketRate > 0 then
							testdelay =  10000000000 / fixedPacketRate / 8 - (sz + 4)
							delay = (testdelay > 0) and testdelay or 0
							if testdelay < 0 then
								fixedRateAcc = fixedRateAcc + testdelay + (sz + 4)
							end
						end
						buf:setDelay(delay)
						prev = ts
						numberOfPackets = numberOfPackets - 1
					else
						break
					end
				end
			end
		else
			if loop then
				pcapFile:reset()
			else
				pcapFile:close()
				mg.sleepMillis(1500)
				mg.stop()
				mg.sleepMillis(1500)
				os.exit(0) -- ending moongen forcefully
				return
			end
		end
		if rateLimiter then
			rateLimiter:sendN(bufs, n)
		else
			queue:sendN(bufs, n)
		end
	end
end

