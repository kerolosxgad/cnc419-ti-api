const multer = require('multer');
const fs = require('fs');
const path = require('path');

const uploadDir = process.env.UPLOAD_PATH || path.join(__dirname, '..', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir),
    filename: (_, file, cb) =>
        cb(null, `${Date.now()}-${Math.round(Math.random() * 1e6)}${path.extname(file.originalname)}`)
});

// 1️⃣  List the MIME types you want to accept
const ALLOWED_MIME = [
    'image/jpeg',
    'image/png',
    'image/jpg',
    'video/mp4',
    'video/quicktime',
    'audio/mp3',
    'audio/wav',
    'application/pdf'
];

// 2️⃣  Reject anything else
const fileFilter = (_req, file, cb) => {
    if (ALLOWED_MIME.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Unsupported file type'), false);
    }
};

const upload = multer({
    storage,
    limits: { fileSize: (process.env.MAX_FILE_SIZE || 100) * 1024 * 1024 }, // Default 100 MB
    fileFilter
});

module.exports = upload;
