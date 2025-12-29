require("dotenv").config();
require("./services/logger"); // Initialize custom logger

const express = require("express");
const app = express();
const cors = require("cors");
const ejs = require("ejs");
const rateLimit = require("express-rate-limit");
const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes");
const adminRoutes = require("./routes/adminRoutes");
const threatIntelRoutes = require("./routes/threatIntelRoutes");

// Only trust loopback interfaces (e.g., from nginx or localhost proxy)
app.set("trust proxy", "loopback");

// Rate limiter middleware
const limiter = rateLimit({
  windowMs: process.env.RATE_LIMIT_WINDOW * 60 * 1000 || 5 * 60 * 1000, // 5 minutes default
  max: process.env.RATE_LIMIT_MAX_REQUESTS || 250, // 250 requests default
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests from this IP, please try again later.",
  skip: (req) => {
    // Bypass rate limit for specific IP(s)
    const bypassIPs = ["127.0.0.1", "::1"]; // Add your IPs here
    return bypassIPs.includes(req.ip);
  },
});

// Apply rate limiter to all requests
app.use(limiter);

// Middleware for parsing JSON bodies
app.use(express.json());

// Middleware for CORS
const corsOptions = {
  origin: ["http://localhost:3000"],
  credentials: true,
  optionsSuccessStatus: 200,
};

// Apply CORS middleware with options
app.use(cors(corsOptions));
// app.use(cors()); // Close CORS rules

// Set EJS as the view engine
app.set("view engine", "ejs");

// Set the directory where your views are located
app.set("views", __dirname + "/views");

// Use authentication routes
app.use("/auth", authRoutes);

// User profile route
app.use("/user", userRoutes);

// Admin profile route
app.use("/admin", adminRoutes);

// Threat Intelligence routes
app.use("/threat-intel", threatIntelRoutes);

// Serve static files from the uploads directory
app.use("/uploads", express.static("uploads"));

// Serve static files from the public directory
app.use("/public", express.static("public"));

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ status: "OK", message: "CNC419 TI Project is healthy" });
});

// Serve the main page with ASCII art
app.get("/", (req, res) => {
  res.type("text/plain").send(`
           ((((((                               ((((((          
         (((&@@((((                           ((((@@#(((        
      ((((@@@@@@@@((((                     ((((@@@@@@@@((((     
    (((#@@@@@@@@@@@@((((                 (((#&@@@@@@@@@@@((((   
 ((((@@@@@@@@@@@@@@@@@@((((           ((((&&&&&@@@@@@@@@@@@@((((
 ((((@@@@@@@@@@@@@@@@@@@@@(((*     ((((%&&&&&&@@@@@@@@@@@@@@((((
   ((((@@@@@@@@@@@@@@@@@@@@@(((( ((((%%%&&&&&&&@@@@@@@@@@@(((.  
      ((((@@@@@@@@@@@@@@@@@@@@@((((#%%%%&&&&&&@@@@@@@@@((((     
        ((((@@@@@@@@@@@@@@@@@@@@@((((%%%&&&&&&&@@@@@@(((        
           ((((@@@@@@@@@@@@@@@@@@@@@((((&&&&&&@@@@((((          
             #(((@@@@@@@@@@@@@@@@@@@@@&(((&&&&&&(((             
                (((@@@@@@@@@@@@@@@@@@@@@(((&&&(((               
                (((@@@@@@@@@@@@@@@@@@@@@%((&&&((*               
              ((((@@@@@@@@@@@@@@@@@@@@@(((#&&&@(((              
            ((((@@@@@@@@@@@@@@@@@@@@@(((#&&&&&&@@((((           
          (((@@@@@@@@@@@@@@@@@@@@@((((%%&&&&&&@@@@@%(((         
       ((((@@@@@@@@@@@@@@@@@@@@@((((%%%%&&&&&&&@@@@@@@((((      
     (((%@@@@@@@@@@@@@@@@@@@@(((((((%%%%&&&&&&@@@@@@@@@@((((    
  ((((@@@@@@@@@@@@@@@@@@@@@((((   ((((%%&&&&&&&@@@@@@@@@@@@(((( 
 (((@@@@@@@@@@@@@@@@@@@@((((         (((#&&&&&@@@@@@@@@@@@@@@(((
   (((#@@@@@@@@@@@@@@@((((             ((((&&&&@@@@@@@@@@@((((  
     ((((@@@@@@@@@@#(((                   (((&@@@@@@@@@@((((    
        ((((@@@@@((((                       ((((@@@@@((((       
          ((((&(((                            *(((#(((,         
             (((                                 (((            
  `);
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("CNC419 TI Project server started");
  console.log(`Server is running on port ${PORT}`);
});

// Start all cron jobs from services dir (files that include ".cron" in their name) when RUN_JOBS=true
if (process.env.RUN_JOBS === "true") {
  const fs = require("fs");
  const path = require("path");

  const servicesDir = path.join(__dirname, "services");

  try {
    const entries = fs.readdirSync(servicesDir);
    const cronFiles = entries.filter((f) => /\.cron(\.|$)/i.test(f));

    if (cronFiles.length === 0) {
      console.log("No cron files found in services directory");
    } else {
      console.log(`Found ${cronFiles.length} cron file(s): ${cronFiles.join(", ")}`);
      cronFiles.forEach((file) => {
        const fullPath = path.join(servicesDir, file);
        try {
          const stat = fs.statSync(fullPath);
          if (!stat.isFile()) {
            console.log(`Skipping non-file: ${file}`);
            return;
          }

          const mod = require(fullPath);

          // Accept startCron export, start export, default.startCron, or module itself if it's a function
          const starter =
            (mod && typeof mod.startCron === "function" && mod.startCron) ||
            (mod && typeof mod.start === "function" && mod.start) ||
            (mod && mod.default && typeof mod.default.startCron === "function" && mod.default.startCron) ||
            (typeof mod === "function" && mod);

          if (!starter) {
            console.warn(`No start function exported from ${file} (expected export "startCron" or "start")`);
            return;
          }

          Promise.resolve()
            .then(() => starter())
            .then(() => console.log(`Started cron from ${file}`))
            .catch((err) => console.error(`Cron ${file} failed to start:`, err));
        } catch (err) {
          console.error(`Error loading cron file ${file}:`, err);
        }
      });
    }
  } catch (err) {
    console.error("Failed to read services directory for cron jobs:", err);
  }
} else {
  console.log("Cron jobs NOT started (set RUN_JOBS=true to enable)");
}

module.exports = app;