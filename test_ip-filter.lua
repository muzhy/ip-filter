local ip_filter = require("ip-filter")

local ip_pattern_arr = {}
table.insert(ip_pattern_arr, {
    ip = "192.168.201.221",
    pattern = "192.168.201.221",
    result = true
})
table.insert(ip_pattern_arr, {
    ip = "192.168.201.221",
    pattern = "192.168.201.222",
    result = false
})
table.insert(ip_pattern_arr, {
    ip = "192.168.201.221",
    pattern = "192.168.201.*",
    result = true
})
table.insert(ip_pattern_arr, {
    ip = "192.168.201.221",
    pattern = "192.168.202.*",
    result = false
})
table.insert(ip_pattern_arr, {
    ip = "192.168.201.221",
    pattern = "192.168.201.255/24",
    result = true
})
table.insert(ip_pattern_arr, {
    ip = "192.168.201.221",
    pattern = "192.168.202.255/24",
    result = false
})
table.insert(ip_pattern_arr, {
    ip = "192.168.201.221",
    pattern = "192.168.100-200.255/24",
    result = false
})
table.insert(ip_pattern_arr, {
    ip = "192.168.201.221",
    pattern = "192.168.100-220.255",
    result = false
})
table.insert(ip_pattern_arr, {
    ip = "192.168.201.221",
    pattern = "192.168.100-200.*",
    result = false
})
table.insert(ip_pattern_arr, {
    ip = "192.168.201.221",
    pattern = "192.168.100-220.*",
    result = true
})

for _, test_case in ipairs(ip_pattern_arr) do
    local filter = ip_filter:new(test_case.pattern)
    if not filter then
        error(string.format("create filter by pattern[%s] failed", test_case.pattern))
    end
    local res = filter:check(test_case.ip)
    print(string.format("ip[%s], pattern[%s], expect result[%s], exce result[%s]", 
        test_case.ip, test_case.pattern, tostring(test_case.result), tostring(res)))
    assert(res == test_case.result)
end