import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// Fix __dirname for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Ensure uploads directory exists
const uploadDir = path.resolve(__dirname, '../uploads/');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `${file.fieldname}-${uniqueSuffix}.txt`); // Force .txt extension
    }
});

const upload = multer({ 
    storage,
    fileFilter: function (req, file, cb) {
        if (
            file.mimetype === 'text/plain' ||
            file.mimetype === 'application/json' ||
            file.mimetype.startsWith('text/')
        ) {
            cb(null, true);
        } else {
            cb(new Error('Only text-based files are allowed'), false);
        }
    }
});

export default upload