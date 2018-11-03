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
	parser:option("-f --fix-rate", "Fixed net data rate in Mbit per second (ignore timestamps in pcap)"):default(0):convert(tonumber):target("fixedRate")
	parser:option("-r --rate-multiplier", "Speed up or slow down replay, 1 = use intervals from file, default = replay as fast as possible"):default(0):convert(tonumber):target("rateMultiplier")
	parser:flag("-l --loop", "Repeat pcap file.")
	local args = parser:parse()
	return args
end

function master(args)
	local edev = device.config{port = args.edev}
	local idev = device.config{port = args.idev, dropEnable = false}
	device.waitForLinks()
	local rateLimiter
	if args.rateMultiplier > 0 and args.fixedRate > 0 then
		print("-r and -f option cannot be set at the same time.")
		return
	end
	if args.rateMultiplier > 0 or args.fixedRate > 0 then
		rateLimiter = limiter:new(edev:getTxQueue(0), "custom")
	end
	mg.startTask("replay", edev:getTxQueue(0), args.file, args.loop, rateLimiter, args.rateMultiplier, args.fixedRate)
	stats.startStatsTask{txDevices = {edev}, rxDevices = {idev}}
	mg.waitForTasks()
end

function replay(queue, file, loop, rateLimiter, multiplier, fixedRate)
	local mempool = memory:createMemPool(4096)
	local bufs = mempool:bufArray()
	local pcapFile = pcap:newReader(file)
	local prev = 0
	local linkSpeed = queue.dev:getLinkStatus().speed
	while mg.running() do
		local n = pcapFile:read(bufs)
		if n > 0 then
			if rateLimiter ~= nil then
				if prev == 0 then
					prev = bufs.array[0].udata64
				end
				for i, buf in ipairs(bufs) do
					if i > n then break end
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
					buf:setDelay(delay)
					prev = ts
				end
			end
		else
			if loop then
				pcapFile:reset()
			else
				break
			end
		end
		if rateLimiter then
			rateLimiter:sendN(bufs, n)
		else
			queue:sendN(bufs, n)
		end
	end
end

