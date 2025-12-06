const { Log } = require("../models/log");

const LOG_LEVELS = {
    error: 0,
    warn: 1,
    info: 2,
    debug: 3
};

const currentLogLevel = LOG_LEVELS[process.env.LOG_LEVEL?.toLowerCase()] ?? LOG_LEVELS.info;

const shouldLog = (level) => {
    return LOG_LEVELS[level] <= currentLogLevel;
};

const logToDatabase = async (level, message) => {
    if (!shouldLog(level)) return;
    
    try {
        await Log.create({ level, message });
    } catch (err) {
        // In case DB logging fails, fall back to native console
        console.warn('Failed to log to DB:', err.message);
    }
};

// Override default console methods
console.log = (...args) => {
    const message = args.map(arg => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' ');
    logToDatabase('info', message);
    if (shouldLog('info')) {
        process.stdout.write(message + '\n');
    }
};

console.warn = (...args) => {
    const message = args.map(arg => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' ');
    logToDatabase('warn', message);
    if (shouldLog('warn')) {
        process.stderr.write(message + '\n');
    }
};

console.error = (...args) => {
    const message = args.map(arg => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' ');
    logToDatabase('error', message);
    if (shouldLog('error')) {
        process.stderr.write(message + '\n');
    }
};

console.debug = (...args) => {
    const message = args.map(arg => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' ');
    logToDatabase('debug', message);
    if (shouldLog('debug')) {
        process.stdout.write(message + '\n');
    }
};