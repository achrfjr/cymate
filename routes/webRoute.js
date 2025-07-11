
import express from "express"
import upload from "../middleware/upload.js";

import {
    SSRFScanController , webConfigScanController , vlunController , cryptoScanController , designCheckerController ,
    softwareIntegrityController , loggingFailureController , identifyFailureController
} from "../controller/webController.js"
import { config } from "dotenv"

const router = express.Router()

// SSRF Scanning
router.post("/ssrf", SSRFScanController)

// Web Config Scanner
router.post("/webconfig", webConfigScanController)
router.post("/vlun", upload.single("file"), vlunController)
router.post("/crypto" , cryptoScanController)
router.post("/design-checker" , designCheckerController)
router.post("/integrity" , upload.single("file") , softwareIntegrityController)
router.post("/logging-failure" , upload.single("file") , loggingFailureController)
router.post("/identify-failure" , identifyFailureController)


// Additional routes can be added here as needed
// Export the router to be used in the main app
// This allows the main app to use this router for handling web-related routes
export default router