
// import mongoose from "mongoose"
// import errorHandler from "../middlewares/errorHnadler.js"

import express from "express";
import {fileURLToPath} from "url"
import errorHandler from "./middleware/errorHandler.js"
import networkRoute from "./routes/networkRoute.js"
import webRoute from "./routes/webRoute.js"
import threatRoute from "./routes/threatRoute.js"
import malwareRoute from "./routes/malwareRoute.js"
import * as path from "path";
import cors from "cors"
import dbConnection from "./db/db.js"
const PORT = process.env.PORT || 3000
const app = express()

app.use(express.json());

// const __filename = fileURLToPath(import.meta.url)
// const __dirname = path.dirname(__filename)
// console.log("Dir Name:" , __dirname , "fileName:" , __filename)

// console.log(typeof path.dirname);  // Should log "function"


(async () => {
    const db = await dbConnection()    
})()

app.use(cors({
    origin: 'http://localhost:3001', 
}))

app.use("/healthz" , (req , res)=>{res.send({status : "ok"})})
app.use("/network" , networkRoute)
app.use("/web" , webRoute)
app.use("/threat" , threatRoute)
app.use("/malware" , malwareRoute)
// app.use("/signup" , signUp)
app.use(errorHandler);

app.listen(PORT, () => {
    console.log(`Server Listen To ${PORT}`)
});