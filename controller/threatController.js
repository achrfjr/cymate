
import { PythonService } from "../services/PythonService.js"


const threatController = async (req, res) => {
    try {
        // it will be domain or ip or url or malware Name or File hash 
        const { query } = req.body
        if (!query) {
            return res.status(400).json({ error: "Query parameter is required" })
        }
        const pythonService = new PythonService()
        const toolOutput = await pythonService.executeScript("Threat Intelligence Scanner", [query])
        // Respond with the result of the processing
        return res.status(200).json({ message: "File processed successfully", result: JSON.parse(toolOutput) })
    } catch (error) {
        console.error("Error processing file:", error)
        return res.status(500).json({ error: error.message })
    }
}
        // Here you would implement the logic to scan the query for threats

export { threatController }