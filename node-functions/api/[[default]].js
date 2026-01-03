import express from 'express';
import path from 'path';
import fs from 'fs';
import 'dotenv/config';
// import { fileURLToPath } from 'url';
import { teo } from "tencentcloud-sdk-nodejs-teo";
import { CommonClient } from "tencentcloud-sdk-nodejs-common";

// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

const app = express();

// Function to read accounts
function getAccounts() {
    let accounts = [];

    // 1. Try EO_ACCOUNTS Environment Variable (JSON String)
    if (process.env.EO_ACCOUNTS) {
        try {
            const parsed = JSON.parse(process.env.EO_ACCOUNTS);
            if (Array.isArray(parsed)) {
                accounts = accounts.concat(parsed);
            }
        } catch (e) {
            console.error("Error parsing EO_ACCOUNTS env var:", e);
        }
    }

    // 2. Try Environment Variables for Multi-Account (EO_ACCOUNT_1_...)
    let i = 1;
    while (process.env[`EO_ACCOUNT_${i}_SECRET_ID`] && process.env[`EO_ACCOUNT_${i}_SECRET_KEY`]) {
        accounts.push({
            id: process.env[`EO_ACCOUNT_${i}_ID`] || `env_account_${i}`,
            // Support NAME or ALIAS for display name
            name: process.env[`EO_ACCOUNT_${i}_NAME`] || process.env[`EO_ACCOUNT_${i}_ALIAS`] || `Account ${i}`,
            secretId: process.env[`EO_ACCOUNT_${i}_SECRET_ID`],
            secretKey: process.env[`EO_ACCOUNT_${i}_SECRET_KEY`]
        });
        i++;
    }

    // 3. Try accounts.json
    try {
        const accountsPath = path.resolve(process.cwd(), 'accounts.json');
        if (fs.existsSync(accountsPath)) {
            const content = fs.readFileSync(accountsPath, 'utf-8');
            const fileAccounts = JSON.parse(content);
            if (Array.isArray(fileAccounts)) {
                // Merge strategies: Append file accounts to env accounts
                accounts = accounts.concat(fileAccounts);
            }
        }
    } catch (err) {
        // Ignore file errors in serverless environment where file might not exist or be accessible
        console.warn("Note: accounts.json not found or not accessible, skipping.");
    }

    // 4. Fallback: If no accounts found, check for single env vars (Legacy support)
    if (accounts.length === 0) {
        if (process.env.SECRET_ID && process.env.SECRET_KEY) {
            accounts.push({
                id: 'default',
                name: process.env.DEFAULT_ACCOUNT_NAME || 'Default Account',
                secretId: process.env.SECRET_ID,
                secretKey: process.env.SECRET_KEY
            });
        }
    }

    return accounts;
}

// Function to read keys
function getKeys(accountId) {
    // 0. Try accounts list (Source: Env Vars or accounts.json)
    const accounts = getAccounts();
    
    if (accountId) {
        // Match by id or name
        const account = accounts.find(a => (a.id && a.id === accountId) || a.name === accountId);
        if (account) {
            return { secretId: account.secretId, secretKey: account.secretKey };
        }
    } else if (accounts.length > 0) {
        // Default to first account if no accountId provided
        return { secretId: accounts[0].secretId, secretKey: accounts[0].secretKey };
    }

    // 1. Fallback to key.txt if no accounts found
    let secretId = '';
    let secretKey = '';

    try {
        // const keyPath = path.resolve(__dirname, '../../key.txt');
        const keyPath = path.resolve(process.cwd(), 'key.txt');
        
        if (fs.existsSync(keyPath)) {
            const content = fs.readFileSync(keyPath, 'utf-8');
            const lines = content.split('\n');
            
            lines.forEach(line => {
                if (line.includes('SecretId') && !secretId) {
                    secretId = line.split('：')[1].trim();
                }
                if (line.includes('SecretKey') && !secretKey) {
                    secretKey = line.split('：')[1].trim();
                }
            });
        }
    } catch (err) {
        console.error("Error reading key.txt:", err);
    }

    return { secretId, secretKey };
}

// Metrics that belong to DescribeTimingL7OriginPullData
const ORIGIN_PULL_METRICS = [
    'l7Flow_outFlux_hy',
    'l7Flow_outBandwidth_hy',
    'l7Flow_request_hy',
    'l7Flow_inFlux_hy',
    'l7Flow_inBandwidth_hy'
];

// Metrics that belong to DescribeTopL7AnalysisData
const TOP_ANALYSIS_METRICS = [
    'l7Flow_outFlux_country',
    'l7Flow_outFlux_province',
    'l7Flow_outFlux_statusCode',
    'l7Flow_outFlux_domain',
    'l7Flow_outFlux_url',
    'l7Flow_outFlux_resourceType',
    'l7Flow_outFlux_sip',
    'l7Flow_outFlux_referers',
    'l7Flow_outFlux_ua_device',
    'l7Flow_outFlux_ua_browser',
    'l7Flow_outFlux_ua_os',
    'l7Flow_outFlux_ua',
    'l7Flow_request_country',
    'l7Flow_request_province',
    'l7Flow_request_statusCode',
    'l7Flow_request_domain',
    'l7Flow_request_url',
    'l7Flow_request_resourceType',
    'l7Flow_request_sip',
    'l7Flow_request_referers',
    'l7Flow_request_ua_device',
    'l7Flow_request_ua_browser',
    'l7Flow_request_ua_os',
    'l7Flow_request_ua'
];

// Metrics that belong to DescribeWebProtectionData (DDoS/Security)
const SECURITY_METRICS = [
    'ccAcl_interceptNum',
    'ccManage_interceptNum',
    'ccRate_interceptNum'
];

// Metrics that belong to DescribeTimingFunctionAnalysisData (Edge Functions)
const FUNCTION_METRICS = [
    'function_requestCount',
    'function_cpuCostTime'
];

app.get('/accounts', (req, res) => {
    const accounts = getAccounts().map(a => ({ id: a.id || a.name, name: a.name }));
    res.json(accounts);
});

app.get('/config', (req, res) => {
    res.json({
        siteName: process.env.SITE_NAME || 'AcoFork 的 EdgeOne 监控大屏',
        siteIcon: process.env.SITE_ICON || 'https://q2.qlogo.cn/headimg_dl?dst_uin=2726730791&spec=0'
    });
});

// Helper to execute a function across all accounts or a specific one
async function executeOnAccount(accountId, fn) {
    if (accountId === 'all') {
        const accounts = getAccounts();
        if (accounts.length === 0) throw new Error("No accounts configured");
        
        // Execute in parallel
        const results = await Promise.all(accounts.map(async (acc) => {
            try {
                return await fn(acc.secretId, acc.secretKey);
            } catch (err) {
                console.error(`Error executing on account ${acc.id}:`, err);
                return null; // Return null on failure
            }
        }));
        
        return results.filter(r => r !== null);
    } else {
        const { secretId, secretKey } = getKeys(accountId);
        if (!secretId || !secretKey) throw new Error("Missing credentials");
        const result = await fn(secretId, secretKey);
        return [result];
    }
}

app.get('/zones', async (req, res) => {
    try {
        const results = await executeOnAccount(req.query.accountId, async (secretId, secretKey) => {
            const TeoClient = teo.v20220901.Client;
            const client = new TeoClient({
                credential: { secretId, secretKey },
                region: "ap-guangzhou",
                profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
            });
            return await client.DescribeZones({});
        });

        // Merge zones and attach accountId source if possible
        // Note: executeOnAccount returns array of results. 
        // We need to know which account each result came from to tag the zones.
        // But executeOnAccount currently abstracts that away.
        
        // Let's refactor this part slightly to tag zones.
        // Since we can't easily change executeOnAccount return type without breaking others,
        // we can do a mapping here if we knew the accounts order, but executeOnAccount filters nulls.
        
        // Alternative: modifying executeOnAccount is risky.
        // Let's just inline the logic for /zones to handle tagging or modify executeOnAccount to return { result, accountId }
        
        // Actually, let's just use getAccounts() locally if accountId is 'all'
        let mergedZones = [];
        let totalCount = 0;
        const requestId = results[0]?.RequestId || 'merged-request';

        if (req.query.accountId === 'all') {
            const accounts = getAccounts();
            // We need to re-run this specifically to tag zones, or we can assume the results map to accounts?
            // No, executeOnAccount filters nulls, so indices might not match.
            
            // Let's re-implement specific parallel logic for /zones to ensure tagging
            const zonePromises = accounts.map(async (acc) => {
                try {
                    const TeoClient = teo.v20220901.Client;
                    const client = new TeoClient({
                        credential: { secretId: acc.secretId, secretKey: acc.secretKey },
                        region: "ap-guangzhou",
                        profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
                    });
                    const data = await client.DescribeZones({});
                    if (data && data.Zones) {
                        // Tag zones with accountId
                        return data.Zones.map(z => ({ ...z, _accountId: acc.id }));
                    }
                } catch (err) {
                    console.error(`Error fetching zones for account ${acc.id}:`, err);
                }
                return [];
            });
            
            const zonesArrays = await Promise.all(zonePromises);
            mergedZones = zonesArrays.flat();
            totalCount = mergedZones.length;

        } else {
            // Single account case
            results.forEach(data => {
                if (data && data.Zones) {
                    // Tag with the requested accountId
                    const tagged = data.Zones.map(z => ({ ...z, _accountId: req.query.accountId }));
                    mergedZones = mergedZones.concat(tagged);
                    totalCount += data.TotalCount || 0;
                }
            });
        }

        res.json({
            TotalCount: totalCount,
            Zones: mergedZones,
            RequestId: requestId
        });
    } catch (err) {
        console.error("Error calling DescribeZones:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/pages/build-count', async (req, res) => {
    try {
        const results = await executeOnAccount(req.query.accountId, async (secretId, secretKey) => {
            const commonClientConfig = {
                credential: { secretId, secretKey },
                region: "ap-guangzhou",
                profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
            };

            const client = new CommonClient("teo.tencentcloudapi.com", "2022-09-01", commonClientConfig);
            let targetZoneId = req.query.zoneId;

            // 1. Auto-discover Zone if needed
            if (!targetZoneId) {
                try {
                    const TeoClient = teo.v20220901.Client;
                    const teoClient = new TeoClient({
                        credential: { secretId, secretKey },
                        region: "ap-guangzhou",
                        profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
                    });
                    
                    const zonesData = await teoClient.DescribeZones({});
                    if (zonesData && zonesData.Zones) {
                        const pagesZone = zonesData.Zones.find(z => z.ZoneName === 'default-pages-zone');
                        if (pagesZone) targetZoneId = pagesZone.ZoneId;
                        else if (zonesData.Zones.length > 0) targetZoneId = zonesData.Zones[0].ZoneId;
                    }
                } catch (zErr) { console.error("Error fetching zones for Pages:", zErr); }
            }

            if (!targetZoneId) return null;

            const params = { "Interface": "pages:DescribePagesDeploymentUsage", "Payload": "{}", "ZoneId": targetZoneId };
            const data = await client.request("DescribePagesResources", params);
            if (data && data.Result) {
                try { data.parsedResult = JSON.parse(data.Result); } catch (e) {}
            }
            return data;
        });

        // Merge Build Counts
        let totalDaily = 0;
        let totalMonth = 0;
        
        results.forEach(res => {
            if (res && res.parsedResult) {
                totalDaily += (res.parsedResult.dplDailyCount || 0);
                totalMonth += (res.parsedResult.dplMonthCount || 0);
            }
        });

        res.json({ parsedResult: { dplDailyCount: totalDaily, dplMonthCount: totalMonth } });
    } catch (err) {
        console.error("Error calling DescribePagesResources:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/pages/cloud-function-requests', async (req, res) => {
    try {
        const results = await executeOnAccount(req.query.accountId, async (secretId, secretKey) => {
            const commonClientConfig = {
                credential: { secretId, secretKey },
                region: "ap-guangzhou",
                profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
            };

            const client = new CommonClient("teo.tencentcloudapi.com", "2022-09-01", commonClientConfig);
            
            let targetZoneId = req.query.zoneId;
            const { startTime, endTime } = req.query;

            // 1. Auto-discover Zone
            if (!targetZoneId) {
                try {
                    const TeoClient = teo.v20220901.Client;
                    const teoClient = new TeoClient({
                        credential: { secretId, secretKey },
                        region: "ap-guangzhou",
                        profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
                    });
                    
                    const zonesData = await teoClient.DescribeZones({});
                    if (zonesData && zonesData.Zones) {
                        const pagesZone = zonesData.Zones.find(z => z.ZoneName === 'default-pages-zone');
                        if (pagesZone) targetZoneId = pagesZone.ZoneId;
                        else if (zonesData.Zones.length > 0) targetZoneId = zonesData.Zones[0].ZoneId;
                    }
                } catch (zErr) { console.error("Error fetching zones for Pages:", zErr); }
            }

            if (!targetZoneId) return null;

            const payload = { ZoneId: targetZoneId, Interval: "hour" };
            if (startTime) payload.StartTime = startTime;
            if (endTime) payload.EndTime = endTime;

            const params = { "ZoneId": targetZoneId, "Interface": "pages:DescribePagesFunctionsRequestDataByZone", "Payload": JSON.stringify(payload) };
            const data = await client.request("DescribePagesResources", params);
            if (data && data.Result) {
                try { data.parsedResult = JSON.parse(data.Result); } catch (e) {}
            }
            return data;
        });

        // Merge Function Requests
        // Structure: parsedResult: { Status, Granularity, Timestamps, Values, TotalValue }
        let mergedTimestamps = [];
        let mergedValues = []; // Should be summed by timestamp
        let mergedTotal = 0;
        
        // We assume all requests return same timestamps if same time range.
        const valueMap = new Map();

        results.forEach(res => {
            if (res && res.parsedResult) {
                const { Timestamps, Values, TotalValue } = res.parsedResult;
                mergedTotal += (TotalValue || 0);
                
                if (Timestamps && Values) {
                    Timestamps.forEach((ts, idx) => {
                        if (!valueMap.has(ts)) {
                            valueMap.set(ts, 0);
                        }
                        valueMap.set(ts, valueMap.get(ts) + (Values[idx] || 0));
                    });
                }
            }
        });

        const sortedTs = Array.from(valueMap.keys()).sort((a,b) => a - b);
        mergedTimestamps = sortedTs;
        mergedValues = sortedTs.map(ts => valueMap.get(ts));

        res.json({
            parsedResult: {
                Status: 'success',
                Granularity: 'hour',
                Timestamps: mergedTimestamps,
                Values: mergedValues,
                TotalValue: mergedTotal
            }
        });

    } catch (err) {
        console.error("Error calling DescribePagesResources for CloudFunction:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/pages/cloud-function-monthly-stats', async (req, res) => {
    try {
        const results = await executeOnAccount(req.query.accountId, async (secretId, secretKey) => {
            const commonClientConfig = {
                credential: { secretId, secretKey },
                region: "ap-guangzhou",
                profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
            };

            const client = new CommonClient("teo.tencentcloudapi.com", "2022-09-01", commonClientConfig);
            let targetZoneId = req.query.zoneId;

            if (!targetZoneId) {
                try {
                    const TeoClient = teo.v20220901.Client;
                    const teoClient = new TeoClient({
                        credential: { secretId, secretKey },
                        region: "ap-guangzhou",
                        profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
                    });
                    const zonesData = await teoClient.DescribeZones({});
                    if (zonesData && zonesData.Zones) {
                        const pagesZone = zonesData.Zones.find(z => z.ZoneName === 'default-pages-zone');
                        if (pagesZone) targetZoneId = pagesZone.ZoneId;
                        else if (zonesData.Zones.length > 0) targetZoneId = zonesData.Zones[0].ZoneId;
                    }
                } catch (zErr) { console.error("Error fetching zones for Pages:", zErr); }
            }

            if (!targetZoneId) return null;

            const params = { "ZoneId": targetZoneId, "Interface": "pages:DescribeHistoryCloudFunctionStats", "Payload": JSON.stringify({ ZoneId: targetZoneId }) };
            const data = await client.request("DescribePagesResources", params);
            if (data && data.Result) {
                try { data.parsedResult = JSON.parse(data.Result); } catch (e) {}
            }
            return data;
        });

        // Merge Monthly Stats
        let totalMem = 0;
        let totalInv = 0;

        results.forEach(res => {
            if (res && res.parsedResult) {
                totalMem += (res.parsedResult.TotalMemDuration || 0);
                totalInv += (res.parsedResult.TotalInvocation || 0);
            }
        });

        res.json({ parsedResult: { TotalMemDuration: totalMem, TotalInvocation: totalInv } });
    } catch (err) {
        console.error("Error calling DescribePagesResources for CloudFunction Monthly:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/traffic', async (req, res) => {
    try {
        const metric = req.query.metric || "l7Flow_flux";
        const now = new Date();
        const formatDate = (date) => date.toISOString().slice(0, 19) + 'Z';
        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        
        const startTime = req.query.startTime || formatDate(yesterday);
        const endTime = req.query.endTime || formatDate(now);
        const interval = req.query.interval;
        const zoneId = req.query.zoneId;
        const zoneIds = zoneId ? [ zoneId ] : [ "*" ];

        console.log(`Requesting metric: ${metric}, StartTime: ${startTime}, EndTime: ${endTime}, Interval: ${interval}, AccountId: ${req.query.accountId}`);

        const results = await executeOnAccount(req.query.accountId, async (secretId, secretKey) => {
            const TeoClient = teo.v20220901.Client;
            const client = new TeoClient({
                credential: { secretId, secretKey },
                region: "ap-guangzhou",
                profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
            });

            const commonClient = new CommonClient(
                "teo.tencentcloudapi.com",
                "2022-09-01",
                {
                    credential: { secretId, secretKey },
                    region: "ap-guangzhou",
                    profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
                }
            );

            let params = {};
            
            if (TOP_ANALYSIS_METRICS.includes(metric)) {
                params = { "StartTime": startTime, "EndTime": endTime, "MetricName": metric, "ZoneIds": zoneIds };
                return await client.DescribeTopL7AnalysisData(params);
            } else if (SECURITY_METRICS.includes(metric)) {
                params = { "StartTime": startTime, "EndTime": endTime, "MetricNames": [ metric ], "ZoneIds": zoneIds };
                if (interval && interval !== 'auto') params["Interval"] = interval;
                return await commonClient.request("DescribeWebProtectionData", params);
            } else if (FUNCTION_METRICS.includes(metric)) {
                let metricNames = [metric];
                if (metric === 'function_cpuCostTime') metricNames = ["function_requestCount", "function_cpuCostTime"];
                params = { "StartTime": startTime, "EndTime": endTime, "MetricNames": metricNames, "ZoneIds": zoneIds };
                if (interval && interval !== 'auto') params["Interval"] = interval;
                return await commonClient.request("DescribeTimingFunctionAnalysisData", params);
            } else {
                params = { "StartTime": startTime, "EndTime": endTime, "MetricNames": [ metric ], "ZoneIds": zoneIds };
                if (interval && interval !== 'auto') params["Interval"] = interval;
                if (ORIGIN_PULL_METRICS.includes(metric)) return await client.DescribeTimingL7OriginPullData(params);
                return await client.DescribeTimingL7AnalysisData(params);
            }
        });

        // Merging Logic
        let mergedData = { Data: [], TimingDataRecords: [], Interval: interval }; // Basic structure
        
        // Helper to merge time series
        const mergeTimeSeries = (targetList, sourceList) => {
            // Assume sourceList is sorted by timestamp. 
            // Since we query same time range, timestamps should match.
            // We use a map to sum values by timestamp.
            const map = new Map();
            
            // Fill map with existing target data
            targetList.forEach(item => {
                map.set(item.Timestamp, { ...item }); // Clone
            });

            sourceList.forEach(item => {
                if (map.has(item.Timestamp)) {
                    const existing = map.get(item.Timestamp);
                    if (existing.Value !== undefined) existing.Value += (item.Value || 0);
                    // For nested structures like Values in DescribeWebProtectionData
                    // Or Detail in TypeValue
                } else {
                    map.set(item.Timestamp, { ...item });
                }
            });
            
            return Array.from(map.values()).sort((a, b) => a.Timestamp - b.Timestamp);
        };

        // Helper to merge Detail arrays (Top Data)
        const mergeDetails = (targetDetails, sourceDetails) => {
            const map = new Map();
            targetDetails.forEach(d => map.set(d.Name, { ...d }));
            
            sourceDetails.forEach(d => {
                if (map.has(d.Name)) {
                    map.get(d.Name).Value += d.Value;
                } else {
                    map.set(d.Name, { ...d });
                }
            });
            
            // Re-sort desc
            return Array.from(map.values()).sort((a, b) => b.Value - a.Value);
        };

        if (results.length > 0) {
            // Clone first result structure as base
            const first = results[0];
            
            // Handle Parse for CommonClient requests which return Result string
             const parseResultIfNeeded = (resObj) => {
                 if (resObj && resObj.Result && typeof resObj.Result === 'string') {
                     try { return JSON.parse(resObj.Result); } catch(e) {}
                 }
                 return resObj;
             };

            if (TOP_ANALYSIS_METRICS.includes(metric)) {
                // Top Analysis: Data[0].DetailData
                let mergedDetail = [];
                results.forEach(res => {
                    if (res && res.Data && res.Data[0] && res.Data[0].DetailData) {
                        mergedDetail = mergeDetails(mergedDetail, res.Data[0].DetailData);
                    }
                });
                mergedData = { Data: [{ MetricName: metric, DetailData: mergedDetail }] };
                
            } else {
                // Time Series (General)
                // Need to handle different structures:
                // 1. Data[].TypeValue[].Detail (TimingL7Analysis)
                // 2. TimingDataRecords[].TypeValue[].Detail (TimingL7OriginPull)
                // 3. Data[].Value (WebProtection - CommonClient) -> needs Result parsing usually? 
                //    Wait, CommonClient.request returns object with "Result" if it's raw, but here we might get parsed object depending on SDK version?
                //    Actually, DescribeWebProtectionData returns a structure like { Data: [...] } where Data has MetricName and Value (array of {Timestamp, Value})
                
                // Let's implement a generic merger based on what we find in the first result
                
                // Strategy: Just loop and sum up everything that looks like a number in the deep structure? 
                // Too risky. Let's be specific.
                
                // Case A: TimingL7AnalysisData (Data -> TypeValue -> Detail)
                if (first.Data && first.Data[0] && first.Data[0].TypeValue) {
                     // We need to merge Detail arrays for each MetricName
                     // But usually we request only 1 metric.
                     const metricName = first.Data[0].TypeValue[0].MetricName;
                     
                     // We will reconstruct the Detail array
                     const timestampMap = new Map();
                     
                     results.forEach(res => {
                         if (res.Data && res.Data[0] && res.Data[0].TypeValue) {
                             const typeVal = res.Data[0].TypeValue.find(t => t.MetricName === metricName);
                             if (typeVal && typeVal.Detail) {
                                 typeVal.Detail.forEach(d => {
                                     if (!timestampMap.has(d.Timestamp)) {
                                         timestampMap.set(d.Timestamp, { Timestamp: d.Timestamp, Value: 0 });
                                     }
                                     timestampMap.get(d.Timestamp).Value += d.Value;
                                 });
                             }
                         }
                     });
                     
                     const mergedDetail = Array.from(timestampMap.values()).sort((a,b) => a.Timestamp - b.Timestamp);
                     
                     // Calculate Sum, Max, Avg
                     let sum = 0, max = 0;
                     mergedDetail.forEach(d => {
                         sum += d.Value;
                         if (d.Value > max) max = d.Value;
                     });
                     const avg = mergedDetail.length > 0 ? sum / mergedDetail.length : 0;
                     
                     mergedData = {
                         Data: [{
                             TypeValue: [{
                                 MetricName: metricName,
                                 Detail: mergedDetail,
                                 Sum: sum,
                                 Max: max,
                                 Avg: avg
                             }]
                         }],
                         Interval: interval
                     };
                }
                // Case B: TimingL7OriginPullData (TimingDataRecords -> TypeValue -> Detail)
                else if (first.TimingDataRecords && first.TimingDataRecords[0] && first.TimingDataRecords[0].TypeValue) {
                    // Same logic as Case A but different root
                     const metricName = first.TimingDataRecords[0].TypeValue[0].MetricName;
                     const timestampMap = new Map();
                     
                     results.forEach(res => {
                         if (res.TimingDataRecords && res.TimingDataRecords[0] && res.TimingDataRecords[0].TypeValue) {
                             const typeVal = res.TimingDataRecords[0].TypeValue.find(t => t.MetricName === metricName);
                             if (typeVal && typeVal.Detail) {
                                 typeVal.Detail.forEach(d => {
                                     if (!timestampMap.has(d.Timestamp)) {
                                         timestampMap.set(d.Timestamp, { Timestamp: d.Timestamp, Value: 0 });
                                     }
                                     timestampMap.get(d.Timestamp).Value += d.Value;
                                 });
                             }
                         }
                     });
                     
                     const mergedDetail = Array.from(timestampMap.values()).sort((a,b) => a.Timestamp - b.Timestamp);
                     
                     let sum = 0, max = 0;
                     mergedDetail.forEach(d => sum += d.Value); // OriginPull doesn't always return Sum/Max in root, but let's compute
                     mergedDetail.forEach(d => { if(d.Value > max) max = d.Value; });
                     const avg = mergedDetail.length > 0 ? sum / mergedDetail.length : 0;

                     mergedData = {
                         TimingDataRecords: [{
                             TypeValue: [{
                                 MetricName: metricName,
                                 Detail: mergedDetail,
                                 Sum: sum,
                                 Max: max,
                                 Avg: avg
                             }]
                         }],
                         Interval: interval
                     };
                }
                // Case C: WebProtectionData / FunctionData (Data -> Value (Array of {Timestamp, Value}))
                // Note: DescribeWebProtectionData returns Data list where each item has MetricName and Value (Array)
                else if (first.Data && first.Data[0] && first.Data[0].Value) {
                    // Assuming structure: Data: [ { MetricName: '...', Value: [ {Timestamp, Value}, ... ] } ]
                    // We need to handle multiple metrics if requested (e.g. function cpu/req)
                    
                    let mergedDataList = [];
                    
                    // Initialize mergedDataList with metrics from first result
                    first.Data.forEach(m => {
                        mergedDataList.push({
                            MetricName: m.MetricName,
                            ValueMap: new Map() // Temp map for summing
                        });
                    });
                    
                    results.forEach(res => {
                        const parsed = parseResultIfNeeded(res);
                        if (parsed && parsed.Data) {
                            parsed.Data.forEach(m => {
                                const target = mergedDataList.find(t => t.MetricName === m.MetricName);
                                if (target && m.Value) {
                                    m.Value.forEach(v => {
                                        if (!target.ValueMap.has(v.Timestamp)) {
                                            target.ValueMap.set(v.Timestamp, { Timestamp: v.Timestamp, Value: 0 });
                                        }
                                        target.ValueMap.get(v.Timestamp).Value += v.Value;
                                    });
                                }
                            });
                        }
                    });
                    
                    // Finalize structure
                    mergedData = {
                        Data: mergedDataList.map(m => ({
                            MetricName: m.MetricName,
                            Value: Array.from(m.ValueMap.values()).sort((a,b) => a.Timestamp - b.Timestamp)
                        })),
                        Interval: interval
                    };
                }
                // Fallback: just return first
                else {
                    mergedData = first;
                }
            }
        }

        res.json(mergedData);
    } catch (err) {
        console.error("Error calling Tencent Cloud API:", err);
        res.status(500).json({ error: err.message });
    }
});

export default app;
