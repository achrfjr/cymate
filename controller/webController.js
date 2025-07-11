import { PythonService } from '../services/PythonService.js'
import fs from "fs/promises"

// Input Method: The script expects a single command-line argument: a URL. ex.(python script.py http://example.com)
const SSRFScanController = async (req, res) => {
    try {
        const domain = req.body.target || req.query.target
        console.log(req.body)
        console.log(req.query)
        
        console.log(`Domain: ${domain}`)
        
        if (!domain) {
            return res.status(400).send('Domain parameter is required')
        }

        const pythonService = new PythonService()
        const toolOutput = await pythonService.executeScript('SSRF Vulnerability Testing', [domain])
        
        res.setHeader('Content-Type', 'application/json')
        return res.status(200).json({result : JSON.parse(toolOutput)})
    } catch (error) {
        console.error('Scan Failed ' , error)
        res.setHeader('Content-Type', 'application/json')
        return res.status(500).json({Error: error.message})
    }
}

const webConfigScanController = async (req, res) => {
    try {
        const { url, username, password, verify_ssl } = req.body

        if (!url) {
            return res.status(400).send('Domain parameter is required')
        }

        console.log(`Scanning domain: ${url}`)

        const args = [url]

        // Optional args
        if (username) args.push(username);
        if (password) args.push(password);
        if (verify_ssl === true || verify_ssl === 'true') args.push('--verify-ssl');

        const pythonService = new PythonService()
        const toolOutput = await pythonService.executeScript('Web Config Scanner', args)

        res.setHeader('Content-Type', 'application/json')
        return res.status(200).json({result : JSON.parse(toolOutput)})
    } catch (error) {
        console.error('Web config scan failed:', error)
        res.setHeader('Content-Type', 'application/json')
        return res.status(500).json({Error: error.message})
    }
}
/*

Method: POST

URL: http://localhost:3000/web/vlun

Body Type: form-data

Key: file → File Upload Field

*/
const vlunController = async (req, res) => {
    try {
        // Check if a file was uploaded
        // Multer adds `req.file`
        if (!req.file) {
            return res.status(400).send('File is required');
        }

        const filePath = req.file.path // Full path to uploaded file
        console.log(`Uploaded file path: ${filePath}`)

        const args = []
        args.push("--file")
        args.push(filePath)

        const pythonService = new PythonService()
        const toolOutput = await pythonService.executeScript('vuln', args)

        res.setHeader('Content-Type', 'application/json')

        // After tool runs successfully delete file

        await fs.unlink(filePath)
        return res.status(200).json({result : JSON.parse(toolOutput)})
    } catch (error) {
        console.error('Vulnerability scan failed:', error)
        res.setHeader('Content-Type', 'application/json')
        return res.status(500).json({Error: error.message})
    }
}

const cryptoScanController = async (req, res) => {
    try {
        // input = string or url
        const { input } = req.body
        if(!input){
            return res.status(400).send('Input parameter is required')
        }
        console.log(`Scanning input: ${input}`)
        const pythonService = new PythonService()
        const toolOutput = await pythonService.executeScript('crypto', [input])
        
        res.setHeader('Content-Type', 'text/plain')
        return res.status(200).json({result : JSON.parse(toolOutput)})
    }catch(error){
        console.log('Crypto Scann Failed' , error)
        res.setHeader('Content-Type', 'application/json')
        return res.status(500).json({Error: error.message})
    }
}

// design-checker
const designCheckerController =  async (req, res) => {
    try {
        // input = string or url
        const { design } = req.body
        if(!design){
            return res.status(400).send('design parameter is required')
        }
        console.log(`Scanning design: ${design}`)
        const pythonService = new PythonService()
        const toolOutput = await pythonService.executeScript('design-checker', [design])
        
        res.setHeader('Content-Type', 'application/json')
        return res.status(200).json({result : JSON.parse(toolOutput)})
    }catch(error){
        console.log('Crypto Scann Failed' , error)
        res.setHeader('Content-Type', 'application/json')
        return res.status(500).json({Error: error.message})
    }
}

const softwareIntegrityController = async (req, res) => {
    try {
        // take a json file in the request body
        if (!req.file) {
            return res.status(400).send('File is required');
        }
        const filePath = req.file.path // Full path to uploaded file
        console.log(`Uploaded file path: ${filePath}`)
        const pythonService = new PythonService()
        const toolOutput = await pythonService.executeScript('Software Integrity', [filePath])
        
        res.setHeader('Content-Type', 'application/json')
        return res.status(200).json({result : JSON.parse(toolOutput)})
    }catch(error){
        console.log('Software Integrity Scan Failed' , error)
        res.setHeader('Content-Type', 'application/json')
        return res.status(500).json({Error: error.message})      
    }

}

const loggingFailureController = async (req, res) => {
    try {
        // file path in the request body
        if (!req.file) {
            return res.status(400).send('File is required')
        }
        const filePath = req.file.path // Full path to uploaded file
        console.log(`Uploaded file path: ${filePath}`)

        const pythonService = new PythonService()
        const toolOutput = await pythonService.executeScript('Logging Failure', [filePath])
        // Extract the last JSON object from the output
        const jsonText = toolOutput.trim().match(/{[\s\S]*}$/)?.[0]

        if (!jsonText) {
            throw new Error('No valid JSON found in script output')
        }
        res.setHeader('Content-Type', 'application/json')
        return res.status(200).json({result : JSON.parse(jsonText)})  
    }catch(error){  
        console.log('Logging Failure Scan Failed' , error)
        res.setHeader('Content-Type', 'application/json')
        return res.status(500).json({Error: error.message})      
    }
}

const identifyFailureController = async (req, res) => {
    try {
        // Accept a single string or separate fields
        let url = req.body.url || req.query.url;
        let auth_endpoint = req.body.auth_endpoint || req.query.auth_endpoint;
        let credentials = req.body.credentials || req.query.credentials;

        // If url is a single string with spaces, split it into parts
        if (url && typeof url === 'string' && url.split(' ').length > 1) {
            const parts = url.split(' ');
            url = parts[0];
            auth_endpoint = parts[1] || auth_endpoint;
            credentials = parts[2] || credentials;
        }

        if (!url) {
            return res.status(400).send('Url parameter is required')
        }
        console.log(`Scanning url: ${url}`)
        
        const args = [url]
        if (auth_endpoint) args.push(auth_endpoint)
        if (credentials) args.push(credentials)

        const pythonService = new PythonService()
        const toolOutput = await pythonService.executeScript('Identification Failure', args)
        
        // Extract the last JSON object from the output
        const jsonText = toolOutput.trim().match(/{[\s\S]*}$/)?.[0]

        if (!jsonText) {
            throw new Error('No valid JSON found in script output')
        }
        res.setHeader('Content-Type', 'application/json')
        return res.status(200).json({result : JSON.parse(jsonText)})  
    }catch(error){  
        console.log('Identify Failure Scan Failed' , error)
        res.setHeader('Content-Type', 'application/json')
        return res.status(500).json({Error: error.message})      
    }
}
// Exporting the controllers 
export {
    SSRFScanController , 
    webConfigScanController ,
    vlunController , 
    cryptoScanController , 
    designCheckerController , 
    softwareIntegrityController ,
    loggingFailureController , 
    identifyFailureController
}








































































































// const ipscanController = async (req, res) => {
//     try {
//         const { ip } = req.query || req.body?.ip || '192.165.1.1/24'
//         const name = req.params.name || 'Service Detection'
//         console.log(`IP: ${ip}, Name: ${name}`)
//         const range = '20-80'
        
//         if(!name || !ip) {
//             return res.status(400).send('Missing required parameters: name or ip');
//         }

//         const pythonService = new PythonService()
        
//         const rawOutput = await pythonService.executeScript(name , [ip , range])
        
//         // Return the complete raw output exactly as from terminal
//         res.setHeader('Content-Type', 'text/plain')
//         return res.send(rawOutput)

//     } catch (error) {
//         console.error('Scan failed:', error)
        
//         // Return error output in same format
//         res.setHeader('Content-Type', 'text/plain')
//         return res.status(500).send(`Error: ${error.message}`)
//     }
// };
