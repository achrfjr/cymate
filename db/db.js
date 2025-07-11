
import { open } from "sqlite";
import sqlite3 from "sqlite3";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let dbInstance = null;  // Singleton instance
let dbInitPromise = null;  // Promise to track initialization

// Promise-based lock.

const dbConnection = async () => {
    if (dbInstance) {
        return dbInstance;  // Return existing instance
    }

    if (!dbInitPromise) {
        // Initialize only once
        dbInitPromise = (async () => {
            try {
                const db = await open({
                    filename: path.join(__dirname, "cymate.sqlite"),
                    driver: sqlite3.Database,
                });
                await db.migrate({
                    migrationsPath: path.join(__dirname, "../migrations"),
                });
                console.log("Database connected and migrations applied successfully.");
                dbInstance = db;  // Set the instance
                return db;
            } catch (error) {
                console.error("Error initializing database:", error);
                dbInitPromise = null;  // Reset the promise in case of error
                throw error;                
            }
        })();
    }
    return dbInitPromise;  // Return the ongoing initialization promise
};

export default dbConnection;












// import sqlConfig from "../server/config.js";
// import sql from "mssql";

// let pool ;

// export const connectDb = async()=>{
//     // Connect to the database
//         try {

//             if(!pool){
//                 pool = await sql.connect(sqlConfig); // Create the connection pool using the configuration
//                 return pool
//             }
//         } catch (error) {
//             console.error('Database connection error:', error)
//             throw error
//         }
// }

// export default connectDb