--- Generates MoonSniff traffic, i.e. packets contain an identifier and a fixed bit pattern
--- Live mode and MSCAP mode require this type of traffic

local lm     = require "libmoon"
local device = require "device"
local memory = require "memory"
local ts     = require "timestamping"
local hist   = require "histogram"
local timer  = require "timer"
local log    = require "log"
local stats  = require "stats"
local bit    = require "bit"
local limiter = require "software-ratecontrol"

local MS_TYPE = 0b01010101
local band = bit.band

function configure(parser)
	parser:description("Generate traffic which can be used by moonsniff to establish latencies induced by a device under test.")
	parser:argument("dev", "Devices to use."):args(2):convert(tonumber)
	parser:option("-v --fix-packetrate", "Approximate send rate in pps."):convert(tonumber):default(10000):target('fixedPacketRate')
	parser:option("-s --src-mac", "Overwrite source MAC address of every sent packet"):default(''):target("srcMAC")
	parser:option("-d --dst-mac", "Overwrite destination MAC address of every sent packet"):default(''):target("dstMAC")
	parser:option("-l --l4-dst", "Set the layer 4 destination port"):default(23432):target("l4dst")
	parser:option("-p --packets", "Send only the number of packets specified"):default(100000):convert(tonumber):target("numberOfPackets")
	parser:option("-x --size", "Packet size in bytes."):convert(tonumber):default(100):target('packetSize')

	return parser:parse()
end

function master(args)
	args.dev[1] = device.config { port = args.dev[1], txQueues = 1 }
	args.dev[2] = device.config { port = args.dev[2], rxQueues = 1 }
	device.waitForLinks()
	local dev0tx = args.dev[1]:getTxQueue(0)
	local dev1rx = args.dev[2]:getRxQueue(0)

	stats.startStatsTask { txDevices = { args.dev[1] }, rxDevices = { args.dev[2] } }

        dstmc = parseMacAddress(args.dstMAC, 0)
	srcmc = parseMacAddress(args.srcMAC, 0)


	rateLimiter = limiter:new(dev0tx, "custom")
	local sender0 = lm.startTask("generateTraffic", dev0tx, args, rateLimiter, dstmc, srcmc)

	sender0:wait()
	lm.stop()
	lm.waitForTasks()
end

function generateTraffic(queue, args, rateLimiter, dstMAC, srcMAC)
	log:info("Trying to enable rx timestamping of all packets, this isn't supported by most nics")
	local pkt_id = 0
	local numberOfPackets = args.numberOfPackets
	local runtime = timer:new(args.time)
	local mempool = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill {
			pktLength = args.packetSize,
			udpDst = args.l4dst
		}
	end)
	local bufs = mempool:bufArray()
	counter = 0
	while lm.running() do
		bufs:alloc(args.packetSize)

		for i, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
			if dstMAC ~= nil then
				pkt.eth:setDst(dstMAC)
			end
			if srcMAC ~= nil then
				pkt.eth:setSrc(srcMAC)
			end

			-- for setters to work correctly, the number is not allowed to exceed 16 bit
			pkt.ip4:setID(band(pkt_id, 0xFFFF))
			pkt.payload.uint32[0] = pkt_id
			pkt.payload.uint8[4] = MS_TYPE
			pkt_id = pkt_id + 1
			numberOfPackets = numberOfPackets - 1
		        delay =  10000000000 / args.fixedPacketRate / 8 - (args.packetSize + 4)
			buf:setDelay(delay)
			counter = counter + 1
			if numberOfPackets <= 0 then
	                        print(i)
				rateLimiter:sendN(bufs, i)
				lm.sleepMillis(1500)
				print(counter)
				lm.stop()
				lm.sleepMillis(1500)
				os.exit(0)
				return
			end
		end
		bufs:offloadUdpChecksums()
		rateLimiter:send(bufs)
	end
end
