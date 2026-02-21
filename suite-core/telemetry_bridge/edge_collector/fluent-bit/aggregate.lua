
local block_count = 0
local latencies = {}
local last_flush = os.time()
local aggregation_interval = tonumber(os.getenv("AGGREGATION_INTERVAL") or "60")

function aggregate_waf_logs(tag, timestamp, record)
    local action = record["action"]
    if action and (string.upper(action) == "BLOCK" or string.upper(action) == "BLOCKED") then
        block_count = block_count + 1
    end
    
    local latency = record["latency_ms"]
    if latency and type(latency) == "number" then
        table.insert(latencies, latency)
    end
    
    local current_time = os.time()
    if current_time - last_flush >= aggregation_interval then
        local latency_p95 = nil
        if #latencies > 0 then
            table.sort(latencies)
            local p95_index = math.floor(#latencies * 0.95)
            if p95_index > 0 and p95_index <= #latencies then
                latency_p95 = latencies[p95_index]
            else
                latency_p95 = latencies[#latencies]
            end
        end
        
        local telemetry = {
            alerts = {
                {
                    rule = "waf-blocks",
                    count = block_count
                }
            },
            latency_ms_p95 = latency_p95
        }
        
        block_count = 0
        latencies = {}
        last_flush = current_time
        
        return 1, timestamp, telemetry
    end
    
    return -1, 0, 0
end
