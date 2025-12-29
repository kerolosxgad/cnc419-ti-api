# CNC419 TI Project API

This repository contains a Node.js Express application that uses **Sequelize** for database interactions and is deployed using **PM2** for process management. This README provides steps to run and deploy the application.

## Prerequisites

Make sure you have the following software installed:

- [Node.js](https://nodejs.org/) (v22 or above)
- [NPM](https://www.npmjs.com/) (Node Package Manager)
- [PM2](https://pm2.keymetrics.io/) (for process management)
- [MariaDB](https://mariadb.org/) (supported database)

## Installation

### 1. Clone the Repository

First, clone the repository to your local machine:

```bash
git clone https://github.com/codexeg/cnc419-ti-api.git
cd cnc419-ti-api
```

### 2. Install Dependencies

Install the required dependencies using NPM:

```bash
npm install
```

This will install the necessary packages listed in the `package.json` file, including Express, Sequelize, and other dependencies.

### 3. Configure Database

Before running the application, make sure to set up your database connection details in a `.env` file at the root of your project. Here’s an example of the required environment variables for MariaDB:

```env
DB_USERNAME=your_username
DB_PASSWORD=your_password
DB_DATABASE=your_database
DB_HOST=localhost
DB_DIALECT=mariadb
```

Make sure to replace:
- `your_username`: Your MariaDB username.
- `your_password`: Your MariaDB password.
- `your_database`: The name of your database.

The application will use these environment variables to configure Sequelize automatically.

Make sure to replace:
- `"your_username"`: Your MariaDB username.
- `"your_password"`: Your MariaDB password.
- `"your_database"`: The name of your database.

### 4. Initialize Sequelize (if needed)

If you haven’t already initialized Sequelize, you can do so by running:

```bash
npx sequelize-cli init
```

This will generate the necessary folders like `models/`, `migrations/`, and `seeders/`.

### 5. Run Migrations

If you have migrations set up (for creating or updating database tables), run the migrations to sync your database:

```bash
npx sequelize-cli db:migrate
```

This will ensure that your database schema is up to date.

### 6. Seed the Database (optional)

If you want to seed the database with some initial data, you can run:

```bash
npx sequelize-cli db:seed:all
```

## Running the Application

### 1. Start the Application with NPM

To run the application in development mode:

```bash
npm run dev
```

By default, the app will be running on `http://localhost:3000`.

### 2. Start the Application with PM2 (for production)

PM2 is a process manager that helps you run and monitor your Node.js application. To start your application with PM2:

First, install PM2 globally if you haven’t done so yet:

```bash
npm install -g pm2
```

Then, use PM2 to start your application:

```bash
pm2 start app.js --name "my-app"
```

This will start your app in the background. You can now visit your application at `http://localhost:3000`.

### 3. View Logs with PM2

To check the logs of your application, use:

```bash
pm2 logs my-app
```

### 4. Stop the Application with PM2

To stop your application, use:

```bash
pm2 stop my-app
```

### 5. Restart the Application with PM2

To restart your app after making changes:

```bash
pm2 restart my-app
```

### 6. Monitor the Application with PM2

PM2 also allows you to monitor the app’s CPU and memory usage in real time:

```bash
pm2 monit
```

## Deployment

### 1. Deploy to a Server

To deploy the app to a production environment, you can use PM2 in combination with your preferred deployment method (e.g., **SSH**, **Docker**, or **CI/CD pipelines**).

Once the app is on your server, follow these steps:

1. SSH into the server and navigate to your project folder.
2. Install the required dependencies:

    ```bash
    npm install
    ```

3. Configure the database settings in `config/config.json` for production.
4. Run the migrations:

    ```bash
    npx sequelize-cli db:migrate
    ```

5. Start the application using PM2:

    ```bash
    pm2 start app.js --name "my-app"
    ```

6. Ensure PM2 starts your application on server restarts:

    ```bash
    pm2 startup
    pm2 save
    ```

This ensures your app is automatically restarted in case of server reboots.

## Additional Commands

### 1. Generate a New Model

You can generate a new Sequelize model using the following command:

```bash
npx sequelize-cli model:generate --name ModelName --attributes attr1:type,attr2:type
```

This will generate a new model and a migration file for you to apply.

### 2. Generate a New Migration

To create a new migration file:

```bash
npx sequelize-cli migration:generate --name migration-name
```

This will create a new migration file where you can add your database changes.

## Threat Intelligence API

This project includes a comprehensive Threat Intelligence platform that meets the following requirements:

### Features

✅ **Integration with Multiple TI Feeds**
- URLhaus (Malicious URLs)
- ThreatFox (IOCs)
- PhishTank (Phishing URLs)
- PhishStats (Phishing URLs)
- Spamhaus (IP blocklists)
- Emerging Threats (Compromised IPs)
- OTX AlienVault (Threat pulses) - *Requires API key*
- MalwareBazaar (Malware samples)
- DShield (OpenIOC and ThreatFeeds)
- MalShare (Malware hashes) - *Requires API key*
- CI Army (Malicious IPs)

✅ **IOC Normalization**
- Automatic detection and normalization of:
  - IPv4 addresses
  - URLs
  - Domains
  - File hashes (MD5, SHA1, SHA256)
  - Email addresses
- Deduplication using fingerprint matching
- Multi-source correlation

✅ **Automated Severity Classification**
- 5-level severity system: Critical, High, Medium, Low, Info
- Classification based on:
  - Source reliability scoring
  - IOC type risk assessment
  - Threat keyword analysis
  - Observation count and confidence metrics
- Automatic confidence scoring (0-100)

✅ **Summary Reports**
- Comprehensive threat intelligence reports including:
  - Total IOC counts and trends
  - Severity breakdown with percentages
  - Top threats (critical/high severity)
  - Source statistics and reliability
  - Data quality metrics
  - Time-based analysis (24h, 7d, 30d, 90d)

### API Endpoints

All endpoints require authentication. Prefix all routes with `/api/threat-intel`

#### Search and Query

**Search IOCs**
```bash
GET /search?query=<value>&type=<type>&source=<source>&severity=<level>&limit=100&offset=0
```

**Get IOC Details**
```bash
GET /ioc/:id
```

**Correlate IOCs**
```bash
GET /correlate?value=<ioc_value>
```
Finds related IOCs by source, description, and severity/type

#### Statistics and Reports

**Get Statistics**
```bash
GET /statistics
```
Returns comprehensive statistics including:
- Total IOC counts
- Breakdown by type, source, and severity
- Top sources with average confidence
- Recent activity (24h)
- Threat level percentage

**Generate Summary Report**
```bash
GET /report/summary?timeRange=7d
```
Time ranges: `24h`, `7d`, `30d`, `90d`

Returns detailed report with:
- Executive summary
- Severity breakdown
- Type and source distributions
- Top threats list
- Data quality metrics
- Feed status

#### Feed Management (Admin Only)

**Trigger Manual Ingestion**
```bash
POST /ingest
```

**Get Fetch Status**
```bash
GET /fetch-status
```

### Configuration

Configure threat intelligence in your `.env` file:

```env
# Enable cron jobs
RUN_JOBS=true

# IOC Sources
IOC_SOURCES_ENABLED=true
IOC_FEEDS_PATH=./data/ingested

# Enable/disable individual sources
IOC_SOURCE_URLHAUS=true
IOC_SOURCE_PHISHTANK=true
IOC_SOURCE_OTX=true
# ... (see .env.example for full list)

# API Keys (optional but recommended)
OTX_API_KEY=your_otx_api_key_here
MALSHARE_API_KEY=your_malshare_api_key_here

# Cron Schedules
CRON_MONTHLY=0 0 1 * *      # Monthly sources
CRON_48_HOURS=0 */48 * * *  # Every 48 hours
CRON_DAILY=0 0 * * *        # Daily sources

# Normalization
NORMALIZE_INPUT_PATH=./data/ingested
NORMALIZE_OUTPUT_PATH=./data/normalized
NORMALIZE_IP_LISTS=true
NORMALIZE_THREAT_INTEL=true
NORMALIZE_PHISHING_URLS=true
NORMALIZE_SOFTWARE_DETECTIONS=true
```

### Example Usage

**Search for a specific IP:**
```bash
curl -H "Authorization: Bearer <token>" \
  "http://localhost:3000/api/threat-intel/search?query=192.168.1.1&type=ipv4"
```

**Get summary report:**
```bash
curl -H "Authorization: Bearer <token>" \
  "http://localhost:3000/api/threat-intel/report/summary?timeRange=7d"
```

**Correlate an IOC:**
```bash
curl -H "Authorization: Bearer <token>" \
  "http://localhost:3000/api/threat-intel/correlate?value=example.com"
```

### Data Management

The system automatically:
- Fetches feeds on configured schedules
- Normalizes and deduplicates IOCs
- Classifies severity and confidence
- Updates observation counts
- Tracks first seen / last seen timestamps

Data is stored in the `ThreatIndicator` model with the following fields:
- `type`: IOC type (ip, domain, url, hash, etc.)
- `value`: The IOC value
- `severity`: Critical, High, Medium, Low, Info
- `confidence`: 0-100 confidence score
- `source`: Original threat feed
- `description`: Context and details
- `observedCount`: Number of times seen
- `firstSeen` / `lastSeen`: Timestamp tracking
- `tags`: JSON array of tags
- `raw`: Original raw data

## Conclusion

You now have a basic setup for running and deploying a Node.js Express application with Sequelize, PM2, and NPM. For further development, you can extend your models, controllers, routes, and integrate additional features.

