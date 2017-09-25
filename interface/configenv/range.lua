return function(env)

	function env.range(start, limit, step)
		step = step or 1
		local v = start - 1

		if not limit then
			return function()
				start = start + step
				return v
			end
		end

		return function()
			v = v + step
			if v > limit then
				v = start
			end

			return v
		end
	end

	function env.randomRange(start, limit)
		return function()
			return math.random(start, limit)
		end
	end

	function env.list(tbl)
		local index, len = 1, #tbl
		return function()
			local v = tbl[index]

			index = index + 1
			if index > len then
				index = 1
			end

			return v
		end
	end

	function env.randomList(tbl)
		local len = #tbl
		return function()
			return tbl[math.random(len)]
		end
	end
end
