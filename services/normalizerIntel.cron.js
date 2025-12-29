require("dotenv").config();

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Papa = require("papaparse");

const logger = console;

const RUN_JOBS = process.env.RUN_JOBS === "true";
const NORMALIZE_INPUT_PATH = process.env.NORMALIZE_INPUT_PATH || "./data/ingested";
const NORMALIZE_OUTPUT_PATH = process.env.NORMALIZE_OUTPUT_PATH || "./data/normalized";

// Feature toggles
const NORMALIZE_IP_LISTS = process.env.NORMALIZE_IP_LISTS === "true";
const NORMALIZE_THREAT_INTEL = process.env.NORMALIZE_THREAT_INTEL === "true";
const NORMALIZE_PHISHING_URLS = process.env.NORMALIZE_PHISHING_URLS === "true";
const NORMALIZE_SOFTWARE_DETECTIONS = process.env.NORMALIZE_SOFTWARE_DETECTIONS === "true";

// Output file names
const OUTPUT_IP_LIST = process.env.OUTPUT_IP_LIST || "merged_ip_list.txt";
const OUTPUT_THREAT_INTEL = process.env.OUTPUT_THREAT_INTEL || "merged_threat_data.csv";
const OUTPUT_PHISHING_URLS = process.env.OUTPUT_PHISHING_URLS || "merged_phishing_data.csv";
const OUTPUT_SOFTWARE_DETECTIONS = process.env.OUTPUT_SOFTWARE_DETECTIONS || "merged_software_data.csv";

// Normalization tracking file
const NORMALIZE_TRACKING_FILE = path.join(NORMALIZE_OUTPUT_PATH, ".normalize_tracking.json");


const IP_REGEX = /\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/g;


function ensureDirectory(dirPath) {
  const absPath = path.resolve(dirPath);
  if (!fs.existsSync(absPath)) {
    fs.mkdirSync(absPath, { recursive: true });
    logger.info(`[Normalize] Created directory: ${absPath}`);
  }
  return absPath;
}

function readFileLines(filePath) {
  try {
    if (!fs.existsSync(filePath)) return [];
    const content = fs.readFileSync(filePath, "utf-8");
    return content.split("\n").map(line => line.trim()).filter(line => line);
  } catch (error) {
    logger.error(`[Normalize] Error reading file ${filePath}: ${error.message}`);
    return [];
  }
}

function writeFileLines(filePath, lines) {
  try {
    fs.writeFileSync(filePath, lines.join("\n"), "utf-8");
    logger.info(`[Normalize] ✓ Wrote ${lines.length} lines to: ${filePath}`);
  } catch (error) {
    logger.error(`[Normalize] Error writing file ${filePath}: ${error.message}`);
  }
}

function parseCSV(filePath) {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    
    // Remove comment lines
    const cleanLines = content
      .split("\n")
      .filter(line => !line.trim().startsWith("#"))
      .join("\n");

    const result = Papa.parse(cleanLines, {
      header: true,
      skipEmptyLines: true,
      transformHeader: (header) => header.trim().toLowerCase().replace(/^#/, "").trim(),
      dynamicTyping: false,
      error: (error) => {
        logger.warn(`[Normalize] CSV parse warning: ${error.message}`);
      }
    });

    return result.data;
  } catch (error) {
    logger.error(`[Normalize] Error parsing CSV ${filePath}: ${error.message}`);
    return [];
  }
}

function writeCSV(filePath, data) {
  try {
    const csv = Papa.unparse(data);
    fs.writeFileSync(filePath, csv, "utf-8");
    logger.info(`[Normalize] ✓ Wrote ${data.length} rows to: ${filePath}`);
  } catch (error) {
    logger.error(`[Normalize] Error writing CSV ${filePath}: ${error.message}`);
  }
}

function detectIndicatorType(value) {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return "ip";
  if (/^https?:\/\//.test(value)) return "url";
  if (/^[a-f0-9]{32}$/i.test(value)) return "md5";
  if (/^[a-f0-9]{40}$/i.test(value)) return "sha1";
  if (/^[a-f0-9]{64}$/i.test(value)) return "sha256";
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(value)) return "domain";
  return "unknown";
}

function getFileHash(filePath) {
  try {
    const content = fs.readFileSync(filePath);
    return crypto.createHash("md5").update(content).digest("hex");
  } catch (error) {
    return null;
  }
}

function getFileTimestamp(filePath) {
  try {
    const stats = fs.statSync(filePath);
    return stats.mtime.toISOString();
  } catch (error) {
    return null;
  }
}

// ============================================================
// NORMALIZATION TRACKING
// ============================================================

function loadNormalizeTracking() {
  try {
    if (fs.existsSync(NORMALIZE_TRACKING_FILE)) {
      const data = fs.readFileSync(NORMALIZE_TRACKING_FILE, "utf-8");
      return JSON.parse(data);
    }
  } catch (error) {
    logger.warn(`[NormalizeTracking] Error loading tracking file: ${error.message}`);
  }
  return {};
}

function saveNormalizeTracking(tracking) {
  try {
    ensureDirectory(NORMALIZE_OUTPUT_PATH);
    fs.writeFileSync(NORMALIZE_TRACKING_FILE, JSON.stringify(tracking, null, 2));
  } catch (error) {
    logger.error(`[NormalizeTracking] Error saving tracking file: ${error.message}`);
  }
}

function isFileProcessed(filePath) {
  const tracking = loadNormalizeTracking();
  const fileName = path.basename(filePath);
  const record = tracking[fileName];
  
  if (!record) {
    return false; // Never processed
  }
  
  // Check if file has changed since last normalization
  const currentHash = getFileHash(filePath);
  const currentTimestamp = getFileTimestamp(filePath);
  
  if (record.hash !== currentHash || record.timestamp !== currentTimestamp) {
    logger.info(`[NormalizeTracking] ${fileName} has changed, will reprocess`);
    return false;
  }
  
  logger.info(`[NormalizeTracking] ${fileName} already processed, skipping`);
  return true;
}

function markFileAsProcessed(filePath, status, count = 0) {
  const tracking = loadNormalizeTracking();
  const fileName = path.basename(filePath);
  
  tracking[fileName] = {
    hash: getFileHash(filePath),
    timestamp: getFileTimestamp(filePath),
    status: status,
    count: count,
    processedAt: new Date().toISOString()
  };
  
  saveNormalizeTracking(tracking);
}

function getNewFiles(directory, prefixes = null) {
  const files = fs.readdirSync(directory);
  const newFiles = [];
  
  for (const file of files) {
    // Skip tracking files
    if (file.startsWith(".")) continue;
    
    // Filter by prefixes if provided
    if (prefixes && !prefixes.some(prefix => file.startsWith(prefix))) {
      continue;
    }
    
    const filePath = path.join(directory, file);
    
    if (!isFileProcessed(filePath)) {
      newFiles.push(filePath);
    }
  }
  
  return newFiles;
}

// ============================================================
// 1. MERGE IP LISTS
// ============================================================

async function mergeIPLists() {
  if (!NORMALIZE_IP_LISTS) {
    logger.info("[MergeIPLists] Disabled in .env");
    return { status: "skipped", reason: "disabled" };
  }

  logger.info("[MergeIPLists] Checking for new IP list files...");

  const inputDir = ensureDirectory(NORMALIZE_INPUT_PATH);
  const outputDir = ensureDirectory(NORMALIZE_OUTPUT_PATH);
  const outputFile = path.join(outputDir, OUTPUT_IP_LIST);

  const prefixes = ["ciarmy", "dshield_openioc", "emerging_threats", "spamhaus"];
  
  // Get only new/updated files
  const newFiles = getNewFiles(inputDir, prefixes);
  
  if (newFiles.length === 0) {
    logger.info("[MergeIPLists] No new files to process");
    return { status: "skipped", reason: "no_new_files" };
  }

  logger.info(`[MergeIPLists] Found ${newFiles.length} new/updated files`);

  const uniqueIPs = new Set();

  // Load existing IPs
  let oldCount = 0;
  if (fs.existsSync(outputFile)) {
    const existing = readFileLines(outputFile);
    existing.forEach(ip => uniqueIPs.add(ip));
    oldCount = uniqueIPs.size;
    logger.info(`[MergeIPLists] Loaded ${oldCount} existing IPs`);
  }

  // Process only new files
  let processedFiles = 0;
  for (const filePath of newFiles) {
    const fileName = path.basename(filePath);
    const lines = readFileLines(filePath);
    let fileIPCount = 0;

    for (let line of lines) {
      // Special handling for Spamhaus (semicolon-separated)
      if (fileName.startsWith("spamhaus")) {
        line = line.split(";")[0].trim();
      }

      // Extract all IPs from the line
      const matches = line.match(IP_REGEX);
      if (matches) {
        matches.forEach(ip => {
          uniqueIPs.add(ip);
          fileIPCount++;
        });
      }
    }

    markFileAsProcessed(filePath, "success", fileIPCount);
    processedFiles++;
    logger.info(`[MergeIPLists] Processed: ${fileName} (${fileIPCount} IPs)`);
  }

  // Write output
  const sortedIPs = Array.from(uniqueIPs).sort();
  writeFileLines(outputFile, sortedIPs);

  const newCount = uniqueIPs.size;
  const added = newCount - oldCount;

  logger.info(`[MergeIPLists] ✓ Complete`);
  logger.info(`[MergeIPLists]   Previous: ${oldCount}`);
  logger.info(`[MergeIPLists]   Added: ${added}`);
  logger.info(`[MergeIPLists]   Total: ${newCount}`);
  logger.info(`[MergeIPLists]   New files processed: ${processedFiles}`);

  return { status: "success", previous: oldCount, added, total: newCount, files: processedFiles };
}

// ============================================================
// 2. MERGE THREAT INTEL DATA (CSV)
// ============================================================

async function mergeThreatIntelData() {
  if (!NORMALIZE_THREAT_INTEL) {
    logger.info("[MergeThreatIntel] Disabled in .env");
    return { status: "skipped", reason: "disabled" };
  }

  logger.info("[MergeThreatIntel] Checking for new threat intel files...");

  const inputDir = ensureDirectory(NORMALIZE_INPUT_PATH);
  const outputDir = ensureDirectory(NORMALIZE_OUTPUT_PATH);
  const outputFile = path.join(outputDir, OUTPUT_THREAT_INTEL);

  // Get all CSV files
  const allFiles = fs.readdirSync(inputDir).filter(f => f.endsWith(".csv"));
  
  // Filter to relevant files
  const relevantFiles = allFiles.filter(f => 
    !f.startsWith("phishtank") && 
    !f.startsWith("bazaar_recent") &&
    (f.startsWith("urlhaus") || f.startsWith("threatfox"))
  );

  // Get only new/updated files
  const newFiles = relevantFiles
    .map(f => path.join(inputDir, f))
    .filter(filePath => !isFileProcessed(filePath));

  if (newFiles.length === 0) {
    logger.info("[MergeThreatIntel] No new files to process");
    return { status: "skipped", reason: "no_new_files" };
  }

  logger.info(`[MergeThreatIntel] Found ${newFiles.length} new/updated files`);

  const allData = [];
  const seenIndicators = new Set();

  // Load existing data
  let oldCount = 0;
  if (fs.existsSync(outputFile)) {
    const existing = parseCSV(outputFile);
    existing.forEach(row => {
      if (row.indicator) {
        seenIndicators.add(row.indicator);
        allData.push(row);
      }
    });
    oldCount = allData.length;
    logger.info(`[MergeThreatIntel] Loaded ${oldCount} existing indicators`);
  }

  let processedFiles = 0;

  for (const filePath of newFiles) {
    const fileName = path.basename(filePath);
    const rows = parseCSV(filePath);
    let fileIndicatorCount = 0;

    if (rows.length === 0) {
      markFileAsProcessed(filePath, "empty", 0);
      continue;
    }

    for (const row of rows) {
      // Find indicator column
      let indicator = null;

      // Try common column names
      for (const col of ["ioc_value", "url", "indicator", "value"]) {
        if (row[col]) {
          indicator = row[col].trim();
          break;
        }
      }

      // Fallback: check 3rd column for URLs
      if (!indicator) {
        const cols = Object.keys(row);
        if (cols.length > 2 && row[cols[2]] && row[cols[2]].startsWith("http")) {
          indicator = row[cols[2]].trim();
        }
      }

      if (!indicator || seenIndicators.has(indicator)) continue;

      seenIndicators.add(indicator);

      // Detect type
      let indicatorType = row["ioc_type"] || row["indicator_type"];
      if (!indicatorType) {
        if (row["url_status"]) {
          indicatorType = "url";
        } else {
          indicatorType = detectIndicatorType(indicator);
        }
      }

      // Build normalized row
      const normalized = {
        indicator,
        indicator_type: indicatorType,
        threat_type: row["threat_type"] || row["threat"] || "",
        tags: row["tags"] || "",
        reporter: row["reporter"] || "",
        reference: row["reference"] || "",
        last_seen: row["last_seen_utc"] || row["last_seen"] || row["dateadded"] || "",
        source: fileName.replace(/\.(csv|txt)$/, "")
      };

      allData.push(normalized);
      fileIndicatorCount++;
    }

    markFileAsProcessed(filePath, "success", fileIndicatorCount);
    processedFiles++;
    logger.info(`[MergeThreatIntel] Processed: ${fileName} (${fileIndicatorCount} new indicators)`);
  }

  if (allData.length === 0) {
    logger.warn("[MergeThreatIntel] No data to merge");
    return { status: "success", total: 0, files: 0 };
  }

  // Add sequential ID
  allData.forEach((row, index) => {
    row.id = index + 1;
  });

  // Write output
  writeCSV(outputFile, allData);

  const newCount = allData.length;
  const added = newCount - oldCount;

  logger.info(`[MergeThreatIntel] ✓ Complete`);
  logger.info(`[MergeThreatIntel]   Previous: ${oldCount}`);
  logger.info(`[MergeThreatIntel]   Added: ${added}`);
  logger.info(`[MergeThreatIntel]   Total: ${newCount}`);
  logger.info(`[MergeThreatIntel]   New files processed: ${processedFiles}`);

  return { status: "success", previous: oldCount, added, total: newCount, files: processedFiles };
}

// ============================================================
// 3. MERGE PHISHING URLS
// ============================================================

async function mergePhishingURLs() {
  if (!NORMALIZE_PHISHING_URLS) {
    logger.info("[MergePhishing] Disabled in .env");
    return { status: "skipped", reason: "disabled" };
  }

  logger.info("[MergePhishing] Checking for new phishing URL files...");

  const inputDir = ensureDirectory(NORMALIZE_INPUT_PATH);
  const outputDir = ensureDirectory(NORMALIZE_OUTPUT_PATH);
  const outputFile = path.join(outputDir, OUTPUT_PHISHING_URLS);

  // Get all phishing-related files
  const allFiles = fs.readdirSync(inputDir);
  const relevantFiles = allFiles.filter(f => 
    (f.startsWith("phishstats_page") && f.endsWith(".json")) ||
    (f.startsWith("phishtank") && f.endsWith(".csv"))
  );

  // Get only new/updated files
  const newFiles = relevantFiles
    .map(f => path.join(inputDir, f))
    .filter(filePath => !isFileProcessed(filePath));

  if (newFiles.length === 0) {
    logger.info("[MergePhishing] No new files to process");
    return { status: "skipped", reason: "no_new_files" };
  }

  logger.info(`[MergePhishing] Found ${newFiles.length} new/updated files`);

  const phishingData = [];
  const seenURLs = new Set();

  // Load existing data
  let oldCount = 0;
  if (fs.existsSync(outputFile)) {
    const existing = parseCSV(outputFile);
    existing.forEach(row => {
      if (row.url) {
        seenURLs.add(row.url);
        phishingData.push(row);
      }
    });
    oldCount = phishingData.length;
    logger.info(`[MergePhishing] Loaded ${oldCount} existing URLs`);
  }

    let processedFiles = 0;

  for (const filePath of newFiles) {
    const fileName = path.basename(filePath);
    let fileURLCount = 0;

    // PhishStats JSON files
    if (fileName.startsWith("phishstats_page") && fileName.endsWith(".json")) {
      try {
        const content = JSON.parse(fs.readFileSync(filePath, "utf-8"));
        const entries = Array.isArray(content) ? content : [content];

        for (const entry of entries) {
          const url = entry.url || entry.phish_url;
          if (!url || seenURLs.has(url)) continue;

          seenURLs.add(url);
          phishingData.push({
            source: "phishstats",
            url,
            ip: entry.ip || "",
            country: entry.countryname || entry.country || "",
            asn: entry.asn || "",
            date: entry.date || "",
            score: entry.score || "",
            host: entry.host || "",
            domain: entry.domain || "",
            tld: entry.tld || "",
            target: "",
            submission_time: "",
            verified: "",
            online: ""
          });
          fileURLCount++;
        }

        markFileAsProcessed(filePath, "success", fileURLCount);
        processedFiles++;
        logger.info(`[MergePhishing] Processed: ${fileName} (${fileURLCount} new URLs)`);
      } catch (error) {
        logger.error(`[MergePhishing] Error loading ${fileName}: ${error.message}`);
        markFileAsProcessed(filePath, "failed", 0);
      }
    }

    // PhishTank CSV
    else if (fileName.startsWith("phishtank") && fileName.endsWith(".csv")) {
      try {
        const rows = parseCSV(filePath);

        for (const row of rows) {
          const url = row.url || row.phish_url;
          if (!url || seenURLs.has(url)) continue;

          seenURLs.add(url);
          phishingData.push({
            source: "phishtank",
            url,
            ip: "",
            country: "",
            asn: "",
            date: "",
            score: "",
            host: "",
            domain: "",
            tld: "",
            target: row.target || "",
            submission_time: row.submission_time || "",
            verified: row.verified || "",
            online: row.online || ""
          });
          fileURLCount++;
        }

        markFileAsProcessed(filePath, "success", fileURLCount);
        processedFiles++;
        logger.info(`[MergePhishing] Processed: ${fileName} (${fileURLCount} new URLs)`);
      } catch (error) {
        logger.error(`[MergePhishing] Error loading ${fileName}: ${error.message}`);
        markFileAsProcessed(filePath, "failed", 0);
      }
    }
  }

  if (phishingData.length === 0) {
    logger.warn("[MergePhishing] No phishing data to merge");
    return { status: "success", total: 0, files: 0 };
  }

  // Write output
  writeCSV(outputFile, phishingData);

  const newCount = phishingData.length;
  const added = newCount - oldCount;

  logger.info(`[MergePhishing] ✓ Complete`);
  logger.info(`[MergePhishing]   Previous: ${oldCount}`);
  logger.info(`[MergePhishing]   Added: ${added}`);
  logger.info(`[MergePhishing]   Total: ${newCount}`);
  logger.info(`[MergePhishing]   New files processed: ${processedFiles}`);

  return { status: "success", previous: oldCount, added, total: newCount, files: processedFiles };
}

// ============================================================
// 4. MERGE SOFTWARE DETECTIONS (MALWARE SAMPLES)
// ============================================================

async function mergeSoftwareDetections() {
  if (!NORMALIZE_SOFTWARE_DETECTIONS) {
    logger.info("[MergeSoftware] Disabled in .env");
    return { status: "skipped", reason: "disabled" };
  }

  logger.info("[MergeSoftware] Checking for new software detection files...");

  const inputDir = ensureDirectory(NORMALIZE_INPUT_PATH);
  const outputDir = ensureDirectory(NORMALIZE_OUTPUT_PATH);
  const outputFile = path.join(outputDir, OUTPUT_SOFTWARE_DETECTIONS);

  // Get all software-related files
  const allFiles = fs.readdirSync(inputDir);
  const relevantFiles = allFiles.filter(f => 
    (f.startsWith("bazaar_recent") && f.endsWith(".csv")) ||
    (f.startsWith("malshare_getlist") && (f.endsWith(".json") || f.endsWith(".txt"))) ||
    (f.startsWith("bazaar_yara_stats") && f.endsWith(".json"))
  );

  // Get only new/updated files
  const newFiles = relevantFiles
    .map(f => path.join(inputDir, f))
    .filter(filePath => !isFileProcessed(filePath));

  if (newFiles.length === 0) {
    logger.info("[MergeSoftware] No new files to process");
    return { status: "skipped", reason: "no_new_files" };
  }

  logger.info(`[MergeSoftware] Found ${newFiles.length} new/updated files`);

  const allData = [];
  const seenHashes = new Set();

  // Load existing data
  let oldCount = 0;
  if (fs.existsSync(outputFile)) {
    try {
      const existing = parseCSV(outputFile);
      existing.forEach(row => {
        const hash = row.sha256 || row.md5 || row.sha1;
        if (hash) {
          seenHashes.add(hash);
          allData.push(row);
        }
      });
      oldCount = allData.length;
      logger.info(`[MergeSoftware] Loaded ${oldCount} existing samples`);
    } catch (error) {
      logger.error(`[MergeSoftware] Error loading existing file: ${error.message}`);
    }
  }

  let processedFiles = 0;

  for (const filePath of newFiles) {
    const fileName = path.basename(filePath);
    let fileSampleCount = 0;

    // Process Bazaar CSV files
    if (fileName.startsWith("bazaar_recent") && fileName.endsWith(".csv")) {
      try {
        const rows = parseCSV(filePath);

        for (const row of rows) {
          const sha256 = row["sha256_hash"] || row["sha256"];
          const md5 = row["md5_hash"] || row["md5"];
          const sha1 = row["sha1_hash"] || row["sha1"];

          const hash = sha256 || md5 || sha1;
          if (!hash || seenHashes.has(hash)) continue;

          seenHashes.add(hash);
          allData.push({
            sha256: sha256 || "",
            md5: md5 || "",
            sha1: sha1 || "",
            file_name: row["file_name"] || "",
            file_type: row["file_type_guess"] || row["file_type"] || "",
            mime_type: row["mime_type"] || "",
            yara_rule: "",
            source: "bazaar"
          });
          fileSampleCount++;
        }

        markFileAsProcessed(filePath, "success", fileSampleCount);
        processedFiles++;
        logger.info(`[MergeSoftware] Processed: ${fileName} (${fileSampleCount} new samples)`);
      } catch (error) {
        logger.error(`[MergeSoftware] Error loading ${fileName}: ${error.message}`);
        markFileAsProcessed(filePath, "failed", 0);
      }
    }

    // Process MalShare JSON/TXT files
    else if (fileName.startsWith("malshare_getlist") && (fileName.endsWith(".json") || fileName.endsWith(".txt"))) {
      try {
        const content = fs.readFileSync(filePath, "utf-8");
        let entries = [];

        // Try JSON first
        try {
          const data = JSON.parse(content);
          entries = Array.isArray(data) ? data : [data];
        } catch {
          // Fallback to text (one hash per line)
          entries = content.split("\n").filter(line => line.trim()).map(line => ({
            hash: line.trim()
          }));
        }

        for (const entry of entries) {
          const sha256 = entry.sha256 || entry.SHA256;
          const md5 = entry.md5 || entry.MD5;
          const sha1 = entry.sha1 || entry.SHA1;
          const hash = entry.hash || sha256 || md5 || sha1;

          if (!hash || seenHashes.has(hash)) continue;

          seenHashes.add(hash);

          // Detect hash type
          let hashObj = { sha256: "", md5: "", sha1: "" };
          if (hash.length === 64) hashObj.sha256 = hash;
          else if (hash.length === 32) hashObj.md5 = hash;
          else if (hash.length === 40) hashObj.sha1 = hash;

          allData.push({
            ...hashObj,
            file_name: entry.file_name || entry.filename || "",
            file_type: entry.file_type || entry.type || "",
            mime_type: entry.mime_type || "",
            yara_rule: "",
            source: "malshare"
          });
          fileSampleCount++;
        }

        markFileAsProcessed(filePath, "success", fileSampleCount);
        processedFiles++;
        logger.info(`[MergeSoftware] Processed: ${fileName} (${fileSampleCount} new samples)`);
      } catch (error) {
        logger.error(`[MergeSoftware] Error loading ${fileName}: ${error.message}`);
        markFileAsProcessed(filePath, "failed", 0);
      }
    }

    // Process Bazaar YARA stats
    else if (fileName.startsWith("bazaar_yara_stats") && fileName.endsWith(".json")) {
      try {
        const content = JSON.parse(fs.readFileSync(filePath, "utf-8"));
        const data = content.data || content;
        const entries = Array.isArray(data) ? data : [data];

        for (const entry of entries) {
          const sha256 = entry.sha256_hash || entry.sha256;
          const md5 = entry.md5_hash || entry.md5;
          const hash = sha256 || md5;

          if (!hash || seenHashes.has(hash)) continue;

          seenHashes.add(hash);
          allData.push({
            sha256: sha256 || "",
            md5: md5 || "",
            sha1: "",
            file_name: entry.file_name || "",
            file_type: entry.file_type || "",
            mime_type: "",
            yara_rule: entry.yara_rule || "",
            source: "bazaar_yara"
          });
          fileSampleCount++;
        }

        markFileAsProcessed(filePath, "success", fileSampleCount);
        processedFiles++;
        logger.info(`[MergeSoftware] Processed: ${fileName} (${fileSampleCount} new samples)`);
      } catch (error) {
        logger.error(`[MergeSoftware] Error loading ${fileName}: ${error.message}`);
        markFileAsProcessed(filePath, "failed", 0);
      }
    }
  }

  if (allData.length === 0) {
    logger.warn("[MergeSoftware] No software detection data to merge");
    return { status: "success", total: 0, files: 0, previous: 0, added: 0 };
  }

  // Write output
  writeCSV(outputFile, allData);

  const newCount = allData.length;
  const added = newCount - oldCount;

  logger.info(`[MergeSoftware] ✓ Complete`);
  logger.info(`[MergeSoftware]   Previous: ${oldCount}`);
  logger.info(`[MergeSoftware]   Added: ${added}`);
  logger.info(`[MergeSoftware]   Total: ${newCount}`);
  logger.info(`[MergeSoftware]   New files processed: ${processedFiles}`);

  return { status: "success", previous: oldCount, added, total: newCount, files: processedFiles };
}

// ============================================================
// MASTER NORMALIZE FUNCTION (Event-Driven)
// ============================================================

async function runAllNormalizers() {
  if (!RUN_JOBS) {
    logger.info("[Normalize] Normalization disabled globally (RUN_JOBS=false)");
    return {
      summary: { successful: 0, failed: 0, skipped: 4, total: 4 },
      results: [{ task: "all", status: "skipped", reason: "RUN_JOBS=false" }]
    };
  }

  logger.info("\n╔════════════════════════════════════╗");
  logger.info("║   Normalization Cycle Started      ║");
  logger.info("╚════════════════════════════════════╝\n");

  const startTime = Date.now();
  const results = [];

  // Run all normalizers
  const tasks = [
    { name: "IP Lists", fn: mergeIPLists },
    { name: "Threat Intel", fn: mergeThreatIntelData },
    { name: "Phishing URLs", fn: mergePhishingURLs },
    { name: "Software Detections", fn: mergeSoftwareDetections }
  ];

  for (const task of tasks) {
    try {
      logger.info(`[Normalize] Running: ${task.name}`);
      const result = await task.fn();
      results.push({ task: task.name, ...result });
      
      if (result.status === "success" && result.added > 0) {
        logger.info(`[Normalize] ✓ ${task.name} complete - ${result.added} new entries added\n`);
      } else if (result.status === "skipped") {
        logger.info(`[Normalize] ⊘ ${task.name} skipped - ${result.reason}\n`);
      } else {
        logger.info(`[Normalize] ✓ ${task.name} complete\n`);
      }
    } catch (error) {
      logger.error(`[Normalize] ✗ ${task.name} failed: ${error.message}`);
      results.push({ task: task.name, status: "failed", error: error.message });
    }
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  const successful = results.filter(r => r.status === "success").length;
  const failed = results.filter(r => r.status === "failed").length;
  const skipped = results.filter(r => r.status === "skipped").length;
  const totalAdded = results.reduce((sum, r) => sum + (r.added || 0), 0);

  logger.info("\n╔════════════════════════════════════╗");
  logger.info("║   Normalization Cycle Complete     ║");
  logger.info("╠════════════════════════════════════╣");
  logger.info(`║   Duration: ${duration}s`.padEnd(37) + "║");
  logger.info(`║   Success: ${successful}/${tasks.length}`.padEnd(37) + "║");
  logger.info(`║   Failed: ${failed}/${tasks.length}`.padEnd(37) + "║");
  logger.info(`║   Skipped: ${skipped}/${tasks.length}`.padEnd(37) + "║");
  logger.info(`║   New entries added: ${totalAdded}`.padEnd(37) + "║");
  logger.info("╚════════════════════════════════════╝\n");

  return {
    summary: { successful, failed, skipped, total: tasks.length, duration, totalAdded },
    results
  };
}

// ============================================================
// CHECK FOR NEW FILES
// ============================================================

function hasNewFiles() {
  const inputDir = path.resolve(NORMALIZE_INPUT_PATH);
  
  if (!fs.existsSync(inputDir)) {
    return false;
  }

  const files = fs.readdirSync(inputDir);
  
  for (const file of files) {
    if (file.startsWith(".")) continue; // Skip hidden files
    
    const filePath = path.join(inputDir, file);
    if (!isFileProcessed(filePath)) {
      return true;
    }
  }
  
  return false;
}

// ============================================================
// STATISTICS
// ============================================================

function getNormalizeStats() {
  const outputDir = path.resolve(NORMALIZE_OUTPUT_PATH);
  const stats = {
    outputDirectory: outputDir,
    files: [],
    tracking: loadNormalizeTracking()
  };

  if (!fs.existsSync(outputDir)) {
    return stats;
  }

  const files = [
    { name: OUTPUT_IP_LIST, type: "text" },
    { name: OUTPUT_THREAT_INTEL, type: "csv" },
    { name: OUTPUT_PHISHING_URLS, type: "csv" },
    { name: OUTPUT_SOFTWARE_DETECTIONS, type: "csv" }
  ];

  for (const file of files) {
    const filePath = path.join(outputDir, file.name);
    
    if (fs.existsSync(filePath)) {
      const fileStats = fs.statSync(filePath);
      let count = 0;

      if (file.type === "text") {
        count = readFileLines(filePath).length;
      } else if (file.type === "csv") {
        const rows = parseCSV(filePath);
        count = rows.length;
      }

      stats.files.push({
        name: file.name,
        size: fileStats.size,
        sizeHuman: formatBytes(fileStats.size),
        count,
        lastModified: fileStats.mtime
      });
    } else {
      stats.files.push({
        name: file.name,
        exists: false
      });
    }
  }

  return stats;
}

function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

// ============================================================
// MANUAL TRIGGER
// ============================================================

async function manualNormalize(taskName) {
  const tasks = {
    "ip": mergeIPLists,
    "threat": mergeThreatIntelData,
    "phishing": mergePhishingURLs,
    "software": mergeSoftwareDetections,
    "all": runAllNormalizers
  };

  if (!tasks[taskName]) {
    throw new Error(`Unknown task: ${taskName}. Available: ${Object.keys(tasks).join(", ")}`);
  }

  logger.info(`[ManualNormalize] Running: ${taskName}`);
  const result = await tasks[taskName]();
  return result;
}

// ============================================================
// RESET TRACKING (Utility function)
// ============================================================

function resetTracking() {
  try {
    if (fs.existsSync(NORMALIZE_TRACKING_FILE)) {
      fs.unlinkSync(NORMALIZE_TRACKING_FILE);
      logger.info("[NormalizeTracking] ✓ Tracking file reset");
      return { status: "success", message: "Tracking file deleted, all files will be reprocessed on next run" };
    } else {
      return { status: "success", message: "No tracking file found" };
    }
  } catch (error) {
    logger.error(`[NormalizeTracking] Error resetting tracking: ${error.message}`);
    return { status: "failed", error: error.message };
  }
}

// ============================================================
// INITIALIZE
// ============================================================

function initialize() {
  logger.info("[Normalize] Initializing...");
  ensureDirectory(NORMALIZE_INPUT_PATH);
  ensureDirectory(NORMALIZE_OUTPUT_PATH);

  logger.info("\n╔════════════════════════════════════════════════════════╗");
  logger.info("║   Normalization Configuration                          ║");
  logger.info("╠════════════════════════════════════════════════════════╣");
  logger.info(`║   Enabled: ${RUN_JOBS ? "YES" : "NO"}`.padEnd(57) + "║");
  logger.info(`║   Mode: EVENT-DRIVEN (on new data)`.padEnd(57) + "║");
  logger.info(`║   Input Path: ${NORMALIZE_INPUT_PATH}`.padEnd(57) + "║");
  logger.info(`║   Output Path: ${NORMALIZE_OUTPUT_PATH}`.padEnd(57) + "║");
  logger.info("╠════════════════════════════════════════════════════════╣");
  logger.info(`║   IP Lists: ${NORMALIZE_IP_LISTS ? "✓" : "✗"}`.padEnd(57) + "║");
  logger.info(`║   Threat Intel: ${NORMALIZE_THREAT_INTEL ? "✓" : "✗"}`.padEnd(57) + "║");
  logger.info(`║   Phishing URLs: ${NORMALIZE_PHISHING_URLS ? "✓" : "✗"}`.padEnd(57) + "║");
  logger.info(`║   Software Detections: ${NORMALIZE_SOFTWARE_DETECTIONS ? "✓" : "✗"}`.padEnd(57) + "║");
  logger.info("╚════════════════════════════════════════════════════════╝\n");

  if (!RUN_JOBS) {
    logger.info("[Normalize] Normalization disabled (RUN_JOBS=false)");
    return false;
  }

  logger.info("[Normalize] ✓ Initialization complete");
  return true;
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
  initialize,
  runAllNormalizers,
  mergeIPLists,
  mergeThreatIntelData,
  mergePhishingURLs,
  mergeSoftwareDetections,
  getNormalizeStats,
  manualNormalize,
  hasNewFiles,
  resetTracking
};