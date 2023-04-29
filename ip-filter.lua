local bit = require("bit")

local _M = {}
local mt = { __index = _M }

local PATTERN_TYPE_PURE_IP = 1
local PATTERN_TYPE_NET_SECTION = 2
local PATTERN_TYPE_SUB_NET_MASK = 3

local function str_trim(str)
    return str:match'^()%s*$' and '' or str:match'^%s*(.*%S)'
end

local function split_str_to_array(str, sep, trim)
    if not str or not sep then
        return nil
    end

    local arr = {}

    for s in str:gmatch("([^" .. sep .. "]+)") do
        if trim then 
            table.insert(arr, str_trim(s))
        else
            table.insert(arr, s)
        end
    end

    return arr
end

local function ip4_str_to_num(ip, ip_part_arr)
    if not ip then
        return nil, "no ip"
    end

    if not ip_part_arr then 
        ip_part_arr = split_str_to_array(ip, ".", true)
    end
    
    if not ip_part_arr or #ip_part_arr ~= 4 then
        return nil, "ip format error"
    end

    local ip_num = 0
    for _, part in ipairs(ip_part_arr) do
        local num = tonumber(part)
        if not num then
            return nil, "ip format error"
        end
        ip_num = bit.bor(bit.lshift(ip_num, 8), num)
    end

    return ip_num, nil
end

-- 通过设置的模式串，检查ip是否符合改模式串，
-- 支持的匹配包括纯ip，子网掩码和网络段
-- 网络段支持通配符：192.168.201.* 和 通过'-'指定的范围：192.168.100-255.192
-- 在同一段内*或-只能有一种，如192.168.100-*.102是非法的，
-- 同一个模式的不同段可以有多种，如192.168.100-255.*是合法的
function _M.new(self, pattern)
    -- 目前只支持ip4
    local pattern_part_arr = split_str_to_array(pattern, ".", true)
    if not pattern_part_arr or #pattern_part_arr ~= 4 then
        return nil
    end

    -- 设置了网络段和掩码不能同时支持，若设置了网络段，则掩码不起作用
    local pattern_type = PATTERN_TYPE_PURE_IP
    for i, part in ipairs(pattern_part_arr) do
        local part_num = tonumber(part)
        if not part_num then
            if part == "*" or part:find("-") then
                pattern_type = PATTERN_TYPE_NET_SECTION
            elseif part:find("/") and i == 4 then
                -- 子网掩码，只有到最后才能确定
                if pattern_type ~= PATTERN_TYPE_NET_SECTION then
                    -- 只有不是网络段的时候，掩码才生效
                    pattern_type = PATTERN_TYPE_SUB_NET_MASK
                end
            else
                -- 既不能转换为数字，也不包含*,-,/，视为非法
                return nil
            end
        end
    end

    if pattern_type == PATTERN_TYPE_PURE_IP then
        local ip_num, err = ip4_str_to_num(pattern, pattern_part_arr)
        if not ip_num then
            error(err)
            return nil
        end

        return setmetatable({
            pattern_type = pattern_type,
            pattern = pattern,
            ip_num = ip_num
        }, mt)
    elseif pattern_type == PATTERN_TYPE_NET_SECTION then
        return setmetatable({
            pattern_type = pattern_type,
            pattern = pattern,
            pattern_part_arr = pattern_part_arr
        }, mt)
    elseif pattern_type == PATTERN_TYPE_SUB_NET_MASK then
        local pattern_split_result = split_str_to_array(pattern, '/')
        if not pattern_split_result or #pattern_split_result ~= 2 then
            error("pattern format error")
            return nil
        end
        local pattern_ip_num, err = ip4_str_to_num(pattern_split_result[1], nil)
        if not pattern_ip_num then 
            error(err)
            return nil
        end

        local mask_num = bit.lshift(bit.bnot(0), 32 - tonumber(pattern_split_result[2]))
        local pattern_mask_res = bit.band(mask_num, pattern_ip_num)

        return setmetatable({
            pattern_type = pattern_type,
            pattern = pattern,
            pattern_mask_res = pattern_mask_res,
            mask_num = mask_num
        }, mt)
    else
        return nil
    end
end

function _M.check(self, ip)
    if self.pattern_type == PATTERN_TYPE_PURE_IP then
        return ip == self.pattern
    elseif self.pattern_type == PATTERN_TYPE_SUB_NET_MASK then
        local ip_num, err = ip4_str_to_num(ip, nil)
        if not ip_num then
            error(err)
        end
        local ip_mask_res = bit.band(self.mask_num, ip_num)
        return bit.bxor(ip_mask_res, self.pattern_mask_res) == 0
    elseif self.pattern_type == PATTERN_TYPE_NET_SECTION then
        if not self.pattern_part_arr or #self.pattern_part_arr ~= 4 then
            local err = string.format("pattern[%s] illegal", self.pattern)
            error(err)
        end
        local ip_part_arr = split_str_to_array(ip, ".", true)
        if not ip_part_arr or #ip_part_arr ~= 4 then
            error(string.format("ip[%] illegal", ip))
        end

        for i, ip_part in ipairs(ip_part_arr) do
            if self.pattern_part_arr[i] ~= "*" then           
                local ip_part_num = tonumber(ip_part)
                if not ip_part_num then
                    error(string.format("ip[%] illegal", ip))
                end

                local pattern_part_str = self.pattern_part_arr[i]           
                if pattern_part_str:find("/") then
                    pattern_part_str = pattern_part_str:sub(1, pattern_part_str:find("/") - 1)
                end

                local pattern_part_num = tonumber(pattern_part_str)
                if not pattern_part_num then 
                    local pattern_part_arr = split_str_to_array(pattern_part_str, "-")
                    if not pattern_part_arr or #pattern_part_arr ~= 2 then
                        error(string.format("pattern[%s] illegal", self.pattern))
                    end
                    local lnum = tonumber(pattern_part_arr[1])
                    local rnum = tonumber(pattern_part_arr[2])
                    if not lnum or not rnum then
                        error(string.format("pattern[%s] illegal", self.pattern))
                    end

                    if ip_part_num < lnum or ip_part_num > rnum then 
                        return false
                    end
                else
                    if pattern_part_num ~= ip_part_num then
                        return false
                    end
                end
            end
        end

        return true
    else
        local err = string.format("pattern type[%s] illegal", self.pattern_type)
        error(err)
    end
end

return _M