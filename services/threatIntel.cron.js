require("dotenv").config();

const sequelize = require("sequelize");
const cron = require("node-cron");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const Joi = require("joi");
const zlib = require("zlib");
const { promisify } = require("util");
const JSZip = require("jszip");
const xml2js = require("xml2js");
const { ThreatIndicator } = require("../models/threatIndicator");
const normalizeCron = require("./normalizerIntel.cron.js");
const severityClassifier = require("./severityClassifier");

const logger = console;

// ============================================================
// CONFIGURATION FROM .ENV
// ============================================================

const IOC_FEEDS_PATH = process.env.IOC_FEEDS_PATH || "./data/ingested";
const IOC_SOURCES_ENABLED = process.env.IOC_SOURCES_ENABLED === "true";
const IOC_FETCH_RETRY_ATTEMPTS = parseInt(process.env.IOC_FETCH_RETRY_ATTEMPTS) || 3;
const IOC_FETCH_TIMEOUT_MS = parseInt(process.env.IOC_FETCH_TIMEOUT_MS) || 30000;

// PhishStats config
const PHISHSTATS_LIMIT = parseInt(process.env.PHISHSTATS_LIMIT) || 100;
const PHISHSTATS_PAGES = parseInt(process.env.PHISHSTATS_PAGES) || 3;

// Cron schedules
const CRON_MONTHLY = process.env.CRON_MONTHLY || "0 0 1 * *";
const CRON_48_HOURS = process.env.CRON_48_HOURS || "0 */48 * * *";
const CRON_DAILY = process.env.CRON_DAILY || "0 0 * * *";

// ✅ NEW: Fetch tracking file
const FETCH_TRACKING_FILE = path.join(IOC_FEEDS_PATH, ".fetch_tracking.json");

// ============================================================
// IOC SOURCES CONFIGURATION (13 Active + 1 Commented)
// ============================================================

const IOC_SOURCES = [
  // ===== MONTHLY SOURCES (2 active, 1 commented) =====
  {
    name: "URLhaus",
    key: "urlhaus",
    enabled: process.env.IOC_SOURCE_URLHAUS === "true",
    url: process.env.IOC_URL_URLHAUS,
    type: "csv",
    filename: "urlhaus_online",
    handler: "simple",
    schedule: "monthly",
    ttl: 30 * 24 * 60 * 60 * 1000 // 30 days
  },
  // COMMENTED OUT - Feodo requires subscription
  // {
  //   name: "Feodo",
  //   key: "feodo",
  //   enabled: process.env.IOC_SOURCE_FEODO === "true",
  //   url: process.env.IOC_URL_FEODO,
  //   type: "csv",
  //   filename: "feodo",
  //   handler: "simple",
  //   schedule: "monthly",
  //   ttl: 30 * 24 * 60 * 60 * 1000
  // },
  {
    name: "CI Army",
    key: "ciarmy",
    enabled: process.env.IOC_SOURCE_CIARMY === "true",
    url: process.env.IOC_URL_CIARMY,
    type: "txt",
    filename: "ciarmy",
    handler: "simple",
    schedule: "monthly",
    ttl: 30 * 24 * 60 * 60 * 1000 // 30 days
  },

  // ===== 48-HOUR SOURCE (1) =====
  {
    name: "ThreatFox",
    key: "threatfox",
    enabled: process.env.IOC_SOURCE_THREATFOX === "true",
    url: process.env.IOC_URL_THREATFOX,
    type: "csv",
    filename: "threatfox_full",
    handler: "zip",
    schedule: "48hours",
    ttl: 48 * 60 * 60 * 1000 // 48 hours
  },

  // ===== DAILY SOURCES (10) =====
  {
    name: "PhishTank",
    key: "phishtank",
    enabled: process.env.IOC_SOURCE_PHISHTANK === "true",
    url: process.env.IOC_URL_PHISHTANK,
    type: "csv",
    filename: "phishtank",
    handler: "gzip",
    schedule: "daily",
    ttl: 24 * 60 * 60 * 1000 // 24 hours
  },
  {
    name: "Spamhaus",
    key: "spamhaus",
    enabled: process.env.IOC_SOURCE_SPAMHAUS === "true",
    url: process.env.IOC_URL_SPAMHAUS,
    type: "txt",
    filename: "spamhaus",
    handler: "simple",
    schedule: "daily",
    ttl: 24 * 60 * 60 * 1000 // 24 hours
  },
  {
    name: "Emerging Threats",
    key: "emergingThreats",
    enabled: process.env.IOC_SOURCE_EMERGING_THREATS === "true",
    url: process.env.IOC_URL_EMERGING_THREATS,
    type: "txt",
    filename: "emerging_threats",
    handler: "simple",
    schedule: "daily",
    ttl: 24 * 60 * 60 * 1000 // 24 hours
  },
  {
    name: "OTX",
    key: "otx",
    enabled: process.env.IOC_SOURCE_OTX === "true",
    url: process.env.IOC_URL_OTX,
    type: "json",
    filename: "otx_pulse",
    handler: "otx_api",
    apiKey: process.env.OTX_API_KEY,
    schedule: "daily",
    ttl: 24 * 60 * 60 * 1000 // 24 hours
  },
  {
    name: "Bazaar",
    key: "bazaar",
    enabled: process.env.IOC_SOURCE_BAZAAR === "true",
    url: process.env.IOC_URL_BAZAAR,
    type: "csv",
    filename: "bazaar_recent",
    handler: "simple",
    schedule: "daily",
    ttl: 24 * 60 * 60 * 1000 // 24 hours
  },
  {
    name: "DShield OpenIOC",
    key: "dshield_openioc",
    enabled: process.env.IOC_SOURCE_DSHIELD_OPENIOC === "true",
    url: process.env.IOC_URL_DSHIELD_OPENIOC,
    type: "txt",
    filename: "dshield_openioc",
    handler: "xml_extract",
    schedule: "daily",
    ttl: 24 * 60 * 60 * 1000 // 24 hours
  },
  {
    name: "DShield ThreatFeeds",
    key: "dshield_threatfeeds",
    enabled: process.env.IOC_SOURCE_DSHIELD_THREATFEEDS === "true",
    url: process.env.IOC_URL_DSHIELD_THREATFEEDS,
    type: "txt",
    filename: "dshield_threatfeeds",
    handler: "xml_extract",
    schedule: "daily",
    ttl: 24 * 60 * 60 * 1000 // 24 hours
  },
  {
    name: "MalShare",
    key: "malshare",
    enabled: process.env.IOC_SOURCE_MALSHARE === "true",
    url: process.env.IOC_URL_MALSHARE,
    type: "txt",
    filename: "malshare_getlist",
    handler: "malshare_api",
    apiKey: process.env.MALSHARE_API_KEY,
    schedule: "daily",
    ttl: 24 * 60 * 60 * 1000 // 24 hours
  }
];

// ============================================================
// AXIOS INSTANCE
// ============================================================

const axiosInstance = axios.create({
  timeout: IOC_FETCH_TIMEOUT_MS,
  headers: {
    "User-Agent": "CNC-419 Project/1.0 (Threat Intelligence Platform)",
  },
  maxRedirects: 5,
  validateStatus: (status) => status >= 200 && status < 400
});

// ============================================================
// REGEX PATTERNS FOR IOC EXTRACTION
// ============================================================

const IP_RE = /(?:\d{1,3}\.){3}\d{1,3}/g;
const URL_RE = /https?:\/\/[^\s'",]+/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;

// ============================================================
// FETCH TRACKING FUNCTIONS
// ============================================================

function loadFetchTracking() {
  try {
    if (fs.existsSync(FETCH_TRACKING_FILE)) {
      const data = fs.readFileSync(FETCH_TRACKING_FILE, "utf-8");
      return JSON.parse(data);
    }
  } catch (error) {
    logger.warn(`[FetchTracking] Error loading tracking file: ${error.message}`);
  }
  return {};
}

function saveFetchTracking(tracking) {
  try {
    ensureFeedsPath();
    fs.writeFileSync(FETCH_TRACKING_FILE, JSON.stringify(tracking, null, 2));
  } catch (error) {
    logger.error(`[FetchTracking] Error saving tracking file: ${error.message}`);
  }
}

function shouldFetchSource(source) {
  const tracking = loadFetchTracking();
  const record = tracking[source.key];
  
  if (!record || record.status !== "success") {
    return true; // Never fetched or failed last time
  }
  
  const lastFetch = new Date(record.timestamp);
  const now = new Date();
  const elapsed = now - lastFetch;
  
  if (elapsed >= source.ttl) {
    logger.info(`[${source.name}] TTL expired (${Math.floor(elapsed / (60 * 60 * 1000))}h ago), will fetch`);
    return true;
  }
  
  logger.info(`[${source.name}] ✓ Already fetched recently (${Math.floor(elapsed / (60 * 60 * 1000))}h ago), skipping`);
  return false;
}

function recordFetchResult(source, result) {
  const tracking = loadFetchTracking();
  tracking[source.key] = {
    name: source.name,
    status: result.status,
    timestamp: result.timestamp || new Date(),
    count: result.count || 0,
    error: result.error || null
  };
  saveFetchTracking(tracking);
}

// ============================================================
// DIRECTORY SETUP
// ============================================================

function ensureFeedsPath() {
  const absPath = path.resolve(IOC_FEEDS_PATH);
  if (!fs.existsSync(absPath)) {
    fs.mkdirSync(absPath, { recursive: true });
    logger.info(`[threatIntel] Created feeds directory: ${absPath}`);
  }
  return absPath;
}

// ============================================================
// VALIDATION SCHEMA
// ============================================================

const indicatorSchema = Joi.object({
  type: Joi.string().required(),
  value: Joi.string().required(),
  description: Joi.string().allow("", null),
  firstSeen: Joi.date().optional(),
  lastSeen: Joi.date().optional(),
  source: Joi.string().optional(),
  confidence: Joi.number().min(0).max(100).optional(),
  tags: Joi.array().items(Joi.string()).optional(),
});

function fingerprint(item) {
  return crypto
    .createHash("sha256")
    .update(`${item.type}|${item.value}|${item.source || ""}`)
    .digest("hex");
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function safeGet(url, headers = {}, retries = null) {
  const maxRetries = retries || IOC_FETCH_RETRY_ATTEMPTS;
  let backoff = 2;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await axiosInstance.get(url, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept": "*/*",
          "Accept-Encoding": "gzip, deflate, br",
          "Accept-Language": "en-US,en;q=0.9",
          "Connection": "keep-alive",
          "Cache-Control": "no-cache",
          ...headers
        },
        responseType: "arraybuffer",
        maxRedirects: 5,
        validateStatus: (status) => status >= 200 && status < 400,
        decompress: true,
        timeout: IOC_FETCH_TIMEOUT_MS
      });
      return response;
    } catch (error) {
      const status = error.response?.status;

      if (status && status >= 400 && status < 500 && status !== 429) {
        logger.error(
          `[safeGet] ${url} returned ${status}. Skipping retries.`
        );
        throw error;
      }

      if (attempt < maxRetries) {
        logger.warn(
          `[Retry] ${url} attempt ${attempt} failed: ${status || error.message}. Retrying in ${backoff}s...`
        );
        await sleep(backoff * 1000);
        backoff *= 2;
      } else {
        logger.error(`[Retry] All ${maxRetries} attempts failed for ${url}`);
        throw error;
      }
    }
  }
}

function saveToFile(filename, data, extension = "json") {
  const filePath = path.join(IOC_FEEDS_PATH, `${filename}.${extension}`);
  const content = typeof data === "object" ? JSON.stringify(data, null, 2) : data;

  fs.writeFileSync(filePath, content, "utf-8");
  logger.info(`[IOCFetcher] ✓ Saved: ${filename}.${extension}`);
  return filePath;
}

// ============================================================
// IOC EXTRACTION HELPER
// ============================================================

function extractIocsFromText(text) {
  const found = new Set();
  const regexes = [URL_RE, IP_RE, DOMAIN_RE];

  for (const regex of regexes) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(text)) !== null) {
      found.add(match[0].trim());
    }
  }

  return Array.from(found).sort();
}

// ============================================================
// IOC DETECTION
// ============================================================

function detectIocType(value) {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return "ipv4";
  if (/^https?:\/\//.test(value)) return "url";
  if (/^[a-f0-9]{32}$/i.test(value)) return "md5";
  if (/^[a-f0-9]{64}$/i.test(value)) return "sha256";
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(value)) return "domain";
  return "unknown";
}

// ============================================================
// GENERIC FETCHER FOR ALL IOC SOURCES
// ============================================================

async function genericFetcher(source) {
  if (!source.enabled) {
    logger.info(`[${source.name}] Skipped (disabled in .env)`);
    return { source: source.key, status: "skipped", reason: "disabled" };
  }

  if (!source.url) {
    logger.error(`[${source.name}] Skipped (IOC_URL_${source.key.toUpperCase()} not set in .env)`);
    return { source: source.key, status: "skipped", reason: "url_not_configured" };
  }

  // ✅ Check if we should fetch this source
  if (!shouldFetchSource(source)) {
    return { source: source.key, status: "skipped", reason: "already_fetched" };
  }

  logger.info(`[${source.name}] Starting fetch...`);
  logger.info(`[${source.name}] URL: ${source.url}`);

  try {
    const headers = {};
    
    // Special headers for PhishTank
    if (source.key === "phishtank") {
      headers["Accept"] = "*/*";
      headers["Accept-Encoding"] = "gzip, deflate";
      headers["Referer"] = "https://www.phishtank.com/";
    }

    let result;

    // Handle different source types
    switch (source.handler) {
      case "simple":
        result = await handleSimple(source, headers);
        break;
      
      case "gzip":
        result = await handleGzip(source, headers);
        break;
      
      case "zip":
        result = await handleZip(source, headers);
        break;
      
      case "otx_api":
        result = await handleOtxApi(source);
        break;
      
      case "phishstats_api":
        result = await handlePhishStatsApi(source, headers);
        break;
      
      case "xml_extract":
        result = await handleXmlExtract(source, headers);
        break;
      
      case "malshare_api":
        result = await handleMalshareApi(source);
        break;
      
      default:
        throw new Error(`Unknown handler type: ${source.handler}`);
    }

    // ✅ Record successful fetch
    recordFetchResult(source, result);
    return result;

  } catch (error) {
    logger.error(`[${source.name}] ✗ Failed: ${error.message}`);
    const errorResult = { 
      source: source.key, 
      status: "failed", 
      error: error.message, 
      timestamp: new Date() 
    };
    
    // ✅ Record failed fetch
    recordFetchResult(source, errorResult);
    return errorResult;
  }
}

// ============================================================
// HANDLER FUNCTIONS
// ============================================================

async function handleSimple(source, headers) {
  const response = await safeGet(source.url, headers);
  const content = Buffer.from(response.data).toString("utf-8");
  saveToFile(source.filename, content, source.type);
  const count = content.split("\n").length;
  logger.info(`[${source.name}] ✓ Success (${count} lines)`);
  return { 
    source: source.key, 
    status: "success", 
    count, 
    timestamp: new Date() 
  };
}

async function handleGzip(source, headers) {
  const response = await safeGet(source.url, headers);
  const gunzip = promisify(zlib.gunzip);
  const decompressed = await gunzip(response.data);
  const content = decompressed.toString("utf-8");
  saveToFile(source.filename, content, source.type);
  const count = content.split("\n").length;
  logger.info(`[${source.name}] ✓ Success (${count} lines)`);
  return { 
    source: source.key, 
    status: "success", 
    count, 
    timestamp: new Date() 
  };
}

async function handleZip(source, headers) {
  const response = await safeGet(source.url, headers);
  const zip = new JSZip();
  await zip.loadAsync(response.data);
  const files = Object.keys(zip.files);
  if (!files.length) throw new Error("Empty ZIP archive");
  const content = await zip.files[files[0]].async("string");
  saveToFile(source.filename, content, source.type);
  const count = content.split("\n").length;
  logger.info(`[${source.name}] ✓ Success (${count} lines)`);
  return { 
    source: source.key, 
    status: "success", 
    count, 
    timestamp: new Date() 
  };
}

async function handleOtxApi(source) {
  if (!source.apiKey) {
    throw new Error("OTX_API_KEY not set in .env");
  }
  const headers = { "X-OTX-API-KEY": source.apiKey };
  const response = await safeGet(source.url, headers);
  const data = JSON.parse(Buffer.from(response.data).toString("utf-8"));
  const results = data.results || [];
  
  for (const pulse of results.slice(0, 100)) {
    saveToFile(`${source.filename}_${pulse.id || "unknown"}`, pulse, "json");
  }
  
  logger.info(`[${source.name}] ✓ Success (${results.length} pulses)`);
  return { 
    source: source.key, 
    status: "success", 
    count: results.length, 
    timestamp: new Date() 
  };
}

async function handlePhishStatsApi(source, headers) {
  let totalEntries = 0;
  const seenIds = new Set();

  for (let page = 1; page <= PHISHSTATS_PAGES; page++) {
    const url = `${source.url}?_page=${page}&_perPage=${PHISHSTATS_LIMIT}`;
    logger.info(`[${source.name}] Fetching page ${page}/${PHISHSTATS_PAGES}`);
    
    const response = await safeGet(url, headers);
    const data = JSON.parse(Buffer.from(response.data).toString("utf-8"));
    
    const newEntries = [];
    for (const entry of data) {
      const id = entry.id;
      if (!seenIds.has(id)) {
        seenIds.add(id);
        newEntries.push(entry);
      }
    }
    
    if (newEntries.length > 0) {
      saveToFile(`${source.filename}_page${page}`, newEntries, "json");
      totalEntries += newEntries.length;
    }
    
    await sleep(1000); // Rate limiting
  }
  
  logger.info(`[${source.name}] ✓ Success (${totalEntries} unique entries)`);
  return { 
    source: source.key, 
    status: "success", 
    count: totalEntries, 
    timestamp: new Date() 
  };
}

async function handleXmlExtract(source, headers) {
  const response = await safeGet(source.url, headers);
  const body = response.data;
  
  // Check if XML
  if (body.toString().includes("<?xml")) {
    const text = Buffer.from(body).toString("utf-8");
    const parser = new xml2js.Parser();
    const result = await parser.parseStringPromise(text);
    
    // Extract text from all XML elements
    const extractText = (obj) => {
      let texts = [];
      if (typeof obj === 'string') {
        texts.push(obj);
      } else if (Array.isArray(obj)) {
        obj.forEach(item => texts.push(...extractText(item)));
      } else if (typeof obj === 'object') {
        Object.values(obj).forEach(val => texts.push(...extractText(val)));
      }
      return texts;
    };
    
    const allText = extractText(result).join("\n");
    const iocs = extractIocsFromText(allText);
    
    if (iocs.length > 0) {
      saveToFile(source.filename, iocs.join("\n"), source.type);
      logger.info(`[${source.name}] ✓ Success (${iocs.length} IOCs extracted from XML)`);
      return { 
        source: source.key, 
        status: "success", 
        count: iocs.length, 
        timestamp: new Date() 
      };
    } else {
      logger.warn(`[${source.name}] ⚠ No IOCs found in XML`);
      return { 
        source: source.key, 
        status: "success", 
        count: 0, 
        timestamp: new Date() 
      };
    }
  } else {
    // Fallback to text extraction
    const text = Buffer.from(body).toString("utf-8");
    const iocs = extractIocsFromText(text);
    saveToFile(source.filename, iocs.join("\n"), source.type);
    logger.info(`[${source.name}] ✓ Success (${iocs.length} IOCs extracted)`);
    return { 
      source: source.key, 
      status: "success", 
      count: iocs.length, 
      timestamp: new Date() 
    };
  }
}

async function handleMalshareApi(source) {
  if (!source.apiKey) {
    throw new Error("MALSHARE_API_KEY not set in .env");
  }
  
  const url = `${source.url}?api_key=${source.apiKey}&action=getlist`;
  const response = await safeGet(url);
  const content = Buffer.from(response.data).toString("utf-8");
  
  // Try to parse as JSON first
  try {
    const data = JSON.parse(content);
    saveToFile(source.filename, data, "json");
    const count = Array.isArray(data) ? data.length : Object.keys(data).length;
    logger.info(`[${source.name}] ✓ Success (${count} items)`);
    return { 
      source: source.key, 
      status: "success", 
      count, 
      timestamp: new Date() 
    };
  } catch {
    // Fallback to text
    saveToFile(source.filename, content, source.type);
    const count = content.split("\n").length;
    logger.info(`[${source.name}] ✓ Success (${count} lines)`);
    return { 
      source: source.key, 
      status: "success", 
      count, 
      timestamp: new Date() 
    };
  }
}

// ============================================================
// DATABASE OPERATIONS
// ============================================================

async function upsertIndicators(items) {
  logger.info(`[upsertIndicators] Starting with ${items.length} items`);
  
  const valid = [];

  for (const it of items) {
    const { error, value } = indicatorSchema.validate(it);
    if (error) {
      logger.warn("[upsertIndicators] Invalid indicator skipped:", error.message);
      continue;
    }
    
    // Apply severity classification
    const classification = severityClassifier.classifyIOC(value);
    
    valid.push({
      type: value.type,
      value: value.value,
      description: value.description || "",
      source: value.source || "unknown",
      fingerprint: fingerprint(value),
      observedCount: 1,
      firstSeen: value.firstSeen || new Date(),
      lastSeen: value.lastSeen || new Date(),
      severity: classification.severity,
      confidence: classification.confidence,
      tags: JSON.stringify(value.tags || []),
      raw: value,
    });
  }

  if (!valid.length) {
    logger.warn("[upsertIndicators] No valid indicators to insert.");
    return { created: 0, updated: 0, total: 0 };
  }

  logger.info(`[upsertIndicators] Validated ${valid.length} indicators, inserting into database...`);

  try {
    // Batch processing to avoid packet size errors
    const BATCH_SIZE = 500; // Smaller batches to avoid max_allowed_packet error
    let totalCreated = 0;
    let totalUpdated = 0;
    let totalProcessed = 0;

    for (let i = 0; i < valid.length; i += BATCH_SIZE) {
      const batch = valid.slice(i, i + BATCH_SIZE);
      
      logger.info(`[upsertIndicators] Processing batch ${Math.floor(i / BATCH_SIZE) + 1}/${Math.ceil(valid.length / BATCH_SIZE)} (${batch.length} items)`);
      
      // Check which records already exist
      const fingerprints = batch.map(ind => ind.fingerprint);
      const existingRecords = await ThreatIndicator.findAll({
        where: { fingerprint: fingerprints },
        attributes: ['fingerprint'],
        raw: true
      });
      
      const existingFingerprints = new Set(existingRecords.map(r => r.fingerprint));
      const newRecords = batch.filter(ind => !existingFingerprints.has(ind.fingerprint));
      const updateRecords = batch.filter(ind => existingFingerprints.has(ind.fingerprint));
      
      await ThreatIndicator.bulkCreate(batch, {
        updateOnDuplicate: [
          "description",
          "source",
          "lastSeen",
          "severity",
          "confidence",
          "tags",
          "raw",
          "updatedAt",
        ],
      });

      const fps = batch.map((v) => v.fingerprint);
      await ThreatIndicator.update(
        {
          observedCount: sequelize.literal("observedCount + 1"),
          lastSeen: new Date(),
        },
        { where: { fingerprint: fps } }
      );

      totalCreated += newRecords.length;
      totalUpdated += updateRecords.length;
      totalProcessed += batch.length;
      
      logger.info(`[upsertIndicators] ✓ Batch completed: ${newRecords.length} new, ${updateRecords.length} updated (${totalProcessed}/${valid.length})`);
      
      // Small delay to prevent overwhelming the database
      await new Promise(resolve => setTimeout(resolve, 50));
    }

    logger.info(`[upsertIndicators] ✓ Complete: ${totalCreated} new entries, ${totalUpdated} updated, ${totalProcessed} total processed`);
    
    return { created: totalCreated, updated: totalUpdated, total: totalProcessed };
  } catch (error) {
    logger.error(`[upsertIndicators] ✗ Database error: ${error.message}`);
    logger.error(error.stack);
    throw error;
  }
}

// ============================================================
// FEED PARSING FUNCTIONS
// ============================================================

function parseCSVFeed(filePath, source) {
  const indicators = [];

  if (!fs.existsSync(filePath)) {
    logger.warn(`[threatIntel] Feed file not found: ${filePath}`);
    return indicators;
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content
    .split("\n")
    .map(line => line.trim())
    .filter(line => line && !line.startsWith("#"));

  for (const line of lines) {
    const parts = line.split(",").map(p => p.trim().replace(/['"]/g, ""));

    if (parts.length === 0) continue;

    const value = parts[0];
    const type = detectIocType(value);

    if (type !== "unknown") {
      indicators.push({
        type,
        value,
        source,
        description: parts[1] || `IOC from ${source}`,
        firstSeen: new Date(),
        lastSeen: new Date(),
        confidence: 75,
        tags: [source, type],
      });
    }
  }

  return indicators;
}

function parseTXTFeed(filePath, source) {
  const indicators = [];

  if (!fs.existsSync(filePath)) {
    logger.warn(`[threatIntel] Feed file not found: ${filePath}`);
    return indicators;
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content
    .split("\n")
    .map(line => line.trim())
    .filter(line => line && !line.startsWith("#") && !line.startsWith(";"));

  for (const line of lines) {
    const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);

    if (ipMatch) {
      indicators.push({
        type: "ipv4",
        value: ipMatch[1],
        source,
        description: `IP from ${source}`,
        firstSeen: new Date(),
        lastSeen: new Date(),
        confidence: 80,
        tags: [source, "ipv4"],
      });
    }
  }

  return indicators;
}

function parseOTXPulse(filePath) {
  const indicators = [];

  if (!fs.existsSync(filePath)) {
    return indicators;
  }

  try {
    const content = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    const pulse = content;

    if (pulse.indicators && Array.isArray(pulse.indicators)) {
      for (const ind of pulse.indicators) {
        const type = (ind.type || "").toLowerCase();
        const value = ind.indicator || ind.content;

        if (value) {
          indicators.push({
            type:
              type === "ipv4"
                ? "ipv4"
                : type === "domain"
                ? "domain"
                : type === "url"
                ? "url"
                : type.includes("hash")
                ? "md5"
                : type,
            value,
            source: "OTX",
            description: pulse.name || ind.description || "OTX Indicator",
            firstSeen: new Date(ind.created || pulse.created),
            lastSeen: new Date(ind.modified || pulse.modified),
            confidence: ind.confidence || 70,
            tags: pulse.tags || ["otx"],
          });
        }
      }
    }
  } catch (error) {
    logger.error(`[threatIntel] Error parsing OTX pulse ${filePath}:`, error.message);
  }

  return indicators;
}

function parsePhishStatsFile(filePath) {
  const indicators = [];
  
  try {
    const content = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    const entries = Array.isArray(content) ? content : [content];
    
    for (const entry of entries) {
      const url = entry.url || entry.phish_url;
      if (url) {
        indicators.push({
          type: "url",
          value: url,
          source: "PhishStats",
          description: entry.title || "Phishing URL from PhishStats",
          firstSeen: entry.date ? new Date(entry.date) : new Date(),
          lastSeen: new Date(),
          confidence: 80,
          tags: ["phishstats", "phishing", "url"],
        });
      }
      
      // Extract IP if available
      if (entry.ip) {
        indicators.push({
          type: "ipv4",
          value: entry.ip,
          source: "PhishStats",
          description: `IP hosting phishing site: ${entry.title || url}`,
          firstSeen: entry.date ? new Date(entry.date) : new Date(),
          lastSeen: new Date(),
          confidence: 75,
          tags: ["phishstats", "phishing", "ipv4"],
        });
      }
    }
  } catch (error) {
    logger.error(`[parsePhishStatsFile] Error: ${error.message}`);
  }
  
  return indicators;
}

function parseBazaarYaraFile(filePath) {
  const indicators = [];
  
  try {
    const content = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    const data = content.data || content;
    
    if (Array.isArray(data)) {
      for (const item of data) {
        const hash = item.sha256_hash || item.md5_hash;
        if (hash) {
          indicators.push({
            type: hash.length === 64 ? "sha256" : "md5",
            value: hash,
            source: "BazaarYARA",
            description: `Malware sample - YARA: ${item.yara_rule || "unknown"}`,
            firstSeen: item.first_seen ? new Date(item.first_seen) : new Date(),
            lastSeen: new Date(),
            confidence: 85,
            tags: ["bazaar", "malware", "hash", item.yara_rule || "unknown"],
          });
        }
      }
    }
  } catch (error) {
    logger.error(`[parseBazaarYaraFile] Error: ${error.message}`);
  }
  
  return indicators;
}

// ============================================================
// IOC PROCESSING
// ============================================================

async function processIOCFeeds() {
  const feedsDir = ensureFeedsPath();
  const stats = {
    totalCreated: 0,
    totalUpdated: 0,
    totalProcessed: 0,
    sources: {}
  };

  logger.info(`[processIOCFeeds] Starting to process feeds from: ${feedsDir}`);

  const feedConfigs = [
    // Existing sources
    { file: "urlhaus_online.csv", source: "URLhaus", parser: parseCSVFeed },
    { file: "threatfox_full.csv", source: "ThreatFox", parser: parseCSVFeed },
    { file: "phishtank.csv", source: "PhishTank", parser: parseCSVFeed },
    { file: "spamhaus.txt", source: "Spamhaus", parser: parseTXTFeed },
    { file: "emerging_threats.txt", source: "EmergingThreats", parser: parseTXTFeed },
    { file: "bazaar_recent.csv", source: "Bazaar", parser: parseCSVFeed },
    
    // New sources
    { file: "ciarmy.txt", source: "CIArmy", parser: parseTXTFeed },
    { file: "dshield_openioc.txt", source: "DShieldOpenIOC", parser: parseTXTFeed },
    { file: "dshield_threatfeeds.txt", source: "DShieldThreatFeeds", parser: parseTXTFeed },
    { file: "malshare_getlist.txt", source: "MalShare", parser: parseTXTFeed },
  ];

  for (const config of feedConfigs) {
    const filePath = path.join(feedsDir, config.file);

    if (fs.existsSync(filePath)) {
      logger.info(`[processIOCFeeds] Processing ${config.source}...`);
      
      try {
        const indicators = config.parser(filePath, config.source);
        logger.info(`[processIOCFeeds] Parsed ${indicators.length} indicators from ${config.source}`);

        if (indicators.length > 0) {
          const result = await upsertIndicators(indicators);
          stats.totalCreated += result.created;
          stats.totalUpdated += result.updated;
          stats.totalProcessed += result.total;
          stats.sources[config.source] = result;
          logger.info(`[processIOCFeeds] ✓ ${config.source}: ${result.created} new, ${result.updated} updated`);
        }
      } catch (error) {
        logger.error(`[processIOCFeeds] ✗ Error processing ${config.source}: ${error.message}`);
        stats.sources[config.source] = { error: error.message };
      }
    } else {
      logger.info(`[processIOCFeeds] File not found: ${config.file}`);
    }
  }

  // Process OTX pulses
  logger.info(`[processIOCFeeds] Looking for OTX pulse files...`);
  const otxFiles = fs
    .readdirSync(feedsDir)
    .filter(f => f.startsWith("otx_pulse_") && f.endsWith(".json"));

  logger.info(`[processIOCFeeds] Found ${otxFiles.length} OTX pulse files`);

  for (const otxFile of otxFiles) {
    const filePath = path.join(feedsDir, otxFile);
    try {
      const indicators = parseOTXPulse(filePath);
      if (indicators.length > 0) {
        const result = await upsertIndicators(indicators);
        stats.totalCreated += result.created;
        stats.totalUpdated += result.updated;
        stats.totalProcessed += result.total;
        stats.sources['OTX'] = result;
      }
    } catch (error) {
      logger.error(`[processIOCFeeds] ✗ Error processing ${otxFile}: ${error.message}`);
    }
  }

  // Process PhishStats files
  logger.info(`[processIOCFeeds] Looking for PhishStats files...`);
  const phishstatsFiles = fs
    .readdirSync(feedsDir)
    .filter(f => f.startsWith("phishstats_") && f.endsWith(".json"));

  logger.info(`[processIOCFeeds] Found ${phishstatsFiles.length} PhishStats files`);

  for (const psFile of phishstatsFiles) {
    const filePath = path.join(feedsDir, psFile);
    try {
      const indicators = parsePhishStatsFile(filePath);
      if (indicators.length > 0) {
        const result = await upsertIndicators(indicators);
        stats.totalCreated += result.created;
        stats.totalUpdated += result.updated;
        stats.totalProcessed += result.total;
        stats.sources['PhishStats'] = result;
      }
    } catch (error) {
      logger.error(`[processIOCFeeds] ✗ Error processing ${psFile}: ${error.message}`);
    }
  }

  // Process Bazaar YARA file
  const bazaarYaraFile = path.join(feedsDir, "bazaar_yara_stats.json");
  if (fs.existsSync(bazaarYaraFile)) {
    logger.info(`[processIOCFeeds] Processing Bazaar YARA stats...`);
    try {
      const indicators = parseBazaarYaraFile(bazaarYaraFile);
      if (indicators.length > 0) {
        const result = await upsertIndicators(indicators);
        stats.totalCreated += result.created;
        stats.totalUpdated += result.updated;
        stats.totalProcessed += result.total;
        stats.sources['BazaarYARA'] = result;
      }
    } catch (error) {
      logger.error(`[processIOCFeeds] ✗ Error processing Bazaar YARA: ${error.message}`);
    }
  }

  logger.info(`\n[processIOCFeeds] ═══════════════════════════════════════════`);
  logger.info(`[processIOCFeeds] FINAL SUMMARY:`);
  logger.info(`[processIOCFeeds] • New entries added: ${stats.totalCreated}`);
  logger.info(`[processIOCFeeds] • Existing entries updated: ${stats.totalUpdated}`);
  logger.info(`[processIOCFeeds] • Total records processed: ${stats.totalProcessed}`);
  logger.info(`[processIOCFeeds] • Deduplication rate: ${stats.totalProcessed > 0 ? ((stats.totalUpdated / stats.totalProcessed) * 100).toFixed(1) : 0}%`);
  logger.info(`[processIOCFeeds] ═══════════════════════════════════════════\n`);

  return stats;
}

// ============================================================
// IOC FEEDS INGESTION
// ============================================================

async function ingestIOCFeeds() {
  if (!IOC_SOURCES_ENABLED) {
    logger.warn("[threatIntel] IOC sources disabled globally (IOC_SOURCES_ENABLED=false)");
    return;
  }

  try {
    logger.info("[threatIntel] Starting IOC feeds ingestion...");

    // Run all fetchers
    const results = await runAllFetchers();

    // Process and store in database
    await processIOCFeeds();

    logger.info("[threatIntel] IOC feeds ingestion complete ✅");

    // ✅ NEW: Trigger normalization after successful ingestion
    if (process.env.RUN_JOBS === "true") {
      logger.info("[threatIntel] Triggering normalization for newly fetched data...");
      
      // Check if there are new files to normalize
      if (normalizeCron.hasNewFiles()) {
        const normalizeResults = await normalizeCron.runAllNormalizers();
        logger.info("[threatIntel] ✅ Normalization complete");
      } else {
        logger.info("[threatIntel] ⊘ No new files to normalize");
      }
    }

  } catch (error) {
    logger.error("[threatIntel] IOC feeds ingestion failed:", error.message);
  }
}

// ============================================================
// RUN ALL FETCHERS
// ============================================================

async function runAllFetchers() {
  if (!IOC_SOURCES_ENABLED) {
    logger.info("[IOCFetcher] IOC sources disabled globally in .env");
    return {
      summary: { successful: 0, failed: 0, skipped: IOC_SOURCES.length, total: IOC_SOURCES.length, duration: "0.00" },
      results: [{ source: "all", status: "skipped", reason: "IOC_SOURCES_ENABLED=false" }],
    };
  }

  logger.info("\n╔════════════════════════════════════╗");
  logger.info("║   IOC Fetch Cycle Started          ║");
  logger.info("╚════════════════════════════════════╝\n");

  const startTime = Date.now();
  const results = [];

  // Loop through all configured sources
  for (const source of IOC_SOURCES) {
    try {
      const result = await genericFetcher(source);
      results.push(result);
      await sleep(2000); // Rate limiting between requests
    } catch (error) {
      logger.error(`[IOCFetcher] Fetcher crashed for ${source.name}: ${error.message}`);
      results.push({
        source: source.key,
        status: "crashed",
        error: error.message,
        timestamp: new Date(),
      });
    }
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  const successful = results.filter(r => r.status === "success").length;
  const failed = results.filter(r => r.status === "failed").length;
  const skipped = results.filter(r => r.status === "skipped").length;

  logger.info("\n╔════════════════════════════════════╗");
  logger.info("║   IOC Fetch Cycle Complete         ║");
  logger.info("╠════════════════════════════════════╣");
  logger.info(`║   Duration: ${duration}s`.padEnd(37) + "║");
  logger.info(`║   Success: ${successful}/${IOC_SOURCES.length}`.padEnd(37) + "║");
  logger.info(`║   Failed: ${failed}/${IOC_SOURCES.length}`.padEnd(37) + "║");
  logger.info(`║   Skipped: ${skipped}/${IOC_SOURCES.length}`.padEnd(37) + "║");
  logger.info("╚════════════════════════════════════╝\n");

  return {
    summary: { successful, failed, skipped, total: IOC_SOURCES.length, duration },
    results,
  };
}

// ============================================================
// STATISTICS
// ============================================================

async function getStats() {
  try {
    const totalCount = await ThreatIndicator.count();
    const bySource = await ThreatIndicator.findAll({
      attributes: [
        "source",
        [sequelize.fn("COUNT", sequelize.col("id")), "count"],
      ],
      group: ["source"],
      raw: true,
    });

    const byType = await ThreatIndicator.findAll({
      attributes: [
        "type",
        [sequelize.fn("COUNT", sequelize.col("id")), "count"],
      ],
      group: ["type"],
      raw: true,
    });

    return {
      total: totalCount,
      bySource: bySource.map(s => ({
        source: s.source,
        count: parseInt(s.count),
      })),
      byType: byType.map(t => ({
        type: t.type,
        count: parseInt(t.count),
      })),
    };
  } catch (error) {
    logger.error(`[getStats] Failed: ${error.message}`);
    throw error;
  }
}

// ============================================================
// FETCH TRACKING STATUS
// ============================================================

function getFetchStatus() {
  const tracking = loadFetchTracking();
  const status = {
    lastUpdate: new Date(),
    sources: []
  };

  for (const source of IOC_SOURCES) {
    const record = tracking[source.key];
    status.sources.push({
      name: source.name,
      key: source.key,
      enabled: source.enabled,
      lastFetch: record ? new Date(record.timestamp) : null,
      status: record ? record.status : "never_fetched",
      count: record ? record.count : 0,
      error: record ? record.error : null,
      ttl: source.ttl,
      nextFetch: record ? new Date(new Date(record.timestamp).getTime() + source.ttl) : null
    });
  }

  return status;
}

// ============================================================
// MANUAL FETCH TRIGGER
// ============================================================

async function manualFetch(sourceKey) {
  const source = IOC_SOURCES.find(s => s.key === sourceKey);
  
  if (!source) {
    throw new Error(`Source not found: ${sourceKey}`);
  }

  if (!source.enabled) {
    throw new Error(`Source is disabled: ${sourceKey}`);
  }

  logger.info(`[ManualFetch] Forcing fetch for ${source.name}...`);
  
  // Temporarily bypass TTL check by removing from tracking
  const tracking = loadFetchTracking();
  delete tracking[source.key];
  saveFetchTracking(tracking);

  const result = await genericFetcher(source);
  
  if (result.status === "success") {
    await processIOCFeeds();
    
    // ✅ NEW: Auto-trigger normalization after manual fetch
    if (process.env.RUN_JOBS === "true" && normalizeCron.hasNewFiles()) {
      logger.info("[ManualFetch] Triggering normalization...");
      await normalizeCron.runAllNormalizers();
    }
  }

  return result;
}

// ============================================================
// CRON SCHEDULER WITH SEPARATE SCHEDULES
// ============================================================

function startCron() {
  logger.info("[threatIntel] Initializing...");
  ensureFeedsPath();

  logger.info("\n╔════════════════════════════════════════════════════════╗");
  logger.info("║   Threat Intel Configuration                          ║");
  logger.info("╠════════════════════════════════════════════════════════╣");
  logger.info(`║   IOC Sources Enabled: ${IOC_SOURCES_ENABLED ? "YES" : "NO"}`.padEnd(57) + "║");
  logger.info(`║   Feeds Path: ${IOC_FEEDS_PATH}`.padEnd(57) + "║");
  logger.info(`║   Fetch Tracking: ENABLED`.padEnd(57) + "║");
  logger.info(`║   Auto-Normalize: ${process.env.RUN_JOBS === "true" ? "YES" : "NO"}`.padEnd(57) + "║");
  logger.info("╚════════════════════════════════════════════════════════╝\n");

  if (!IOC_SOURCES_ENABLED) {
    logger.info("[threatIntel] IOC sources disabled (IOC_SOURCES_ENABLED=false)");
    return;
  }

  // ✅ NEW: Initialize normalization module
  if (process.env.RUN_JOBS === "true") {
    normalizeCron.initialize();
  }

  // Run initial ingestion
  logger.info("[threatIntel] Running initial ingestion...");
  ingestIOCFeeds();

  // Group sources by schedule
  const monthlySources = IOC_SOURCES.filter(s => s.schedule === "monthly" && s.enabled);
  const sources48h = IOC_SOURCES.filter(s => s.schedule === "48hours" && s.enabled);
  const dailySources = IOC_SOURCES.filter(s => s.schedule === "daily" && s.enabled);

  // Schedule MONTHLY sources
  if (monthlySources.length > 0) {
    cron.schedule(CRON_MONTHLY, async () => {
      logger.info(`[Cron] Running MONTHLY sources (${CRON_MONTHLY})`);
      for (const source of monthlySources) {
        await genericFetcher(source);
        await sleep(2000);
      }
      await processIOCFeeds();
      
      // ✅ NEW: Auto-trigger normalization
      if (process.env.RUN_JOBS === "true" && normalizeCron.hasNewFiles()) {
        logger.info("[Cron] Triggering normalization...");
        await normalizeCron.runAllNormalizers();
      }
    });
    logger.info(`[Cron] ✓ Monthly sources scheduled (${CRON_MONTHLY}): ${monthlySources.map(s => s.name).join(", ")}`);
  }

  // Schedule 48-HOUR sources
  if (sources48h.length > 0) {
    cron.schedule(CRON_48_HOURS, async () => {
      logger.info(`[Cron] Running 48-HOUR sources (${CRON_48_HOURS})`);
      for (const source of sources48h) {
        await genericFetcher(source);
        await sleep(2000);
      }
      await processIOCFeeds();
      
      // ✅ NEW: Auto-trigger normalization
      if (process.env.RUN_JOBS === "true" && normalizeCron.hasNewFiles()) {
        logger.info("[Cron] Triggering normalization...");
        await normalizeCron.runAllNormalizers();
      }
    });
    logger.info(`[Cron] ✓ 48-hour sources scheduled (${CRON_48_HOURS}): ${sources48h.map(s => s.name).join(", ")}`);
  }

  // Schedule DAILY sources
  if (dailySources.length > 0) {
    cron.schedule(CRON_DAILY, async () => {
      logger.info(`[Cron] Running DAILY sources (${CRON_DAILY})`);
      for (const source of dailySources) {
        await genericFetcher(source);
        await sleep(2000);
      }
      await processIOCFeeds();
      
      // ✅ NEW: Auto-trigger normalization
      if (process.env.RUN_JOBS === "true" && normalizeCron.hasNewFiles()) {
        logger.info("[Cron] Triggering normalization...");
        await normalizeCron.runAllNormalizers();
      }
    });
    logger.info(`[Cron] ✓ Daily sources scheduled (${CRON_DAILY}): ${dailySources.map(s => s.name).join(", ")}`);
  }

  // Log all enabled sources
  const enabledSources = IOC_SOURCES.filter(s => s.enabled);
  logger.info("\n╔════════════════════════════════════════════════════════╗");
  logger.info("║   Active IOC Sources (13 Total)                       ║");
  logger.info("╠════════════════════════════════════════════════════════╣");
  enabledSources.forEach(source => {
    const ttlHours = Math.floor(source.ttl / (60 * 60 * 1000));
    logger.info(`║   ✓ ${source.name} (${source.schedule}, TTL: ${ttlHours}h)`.padEnd(57) + "║");
  });
  logger.info("╚════════════════════════════════════════════════════════╝\n");

  logger.info("[threatIntel] ✓ Cron jobs started successfully");
  
  // Display current fetch status
  const status = getFetchStatus();
  logger.info("\n[FetchTracking] Current status:");
  status.sources.forEach(s => {
    if (s.enabled && s.lastFetch) {
      const age = Math.floor((Date.now() - s.lastFetch.getTime()) / (60 * 60 * 1000));
      logger.info(`  ${s.name}: Last fetched ${age}h ago (${s.status})`);
    }
  });
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
  startCron,
  ingestIOCFeeds,
  runAllFetchers,
  getStats,
  getFetchStatus,
  manualFetch,
  logger,
};