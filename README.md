# Phishing Email Detection System

A comprehensive Python-based phishing email detection application developed for the INF1002 Programming Fundamentals course at SIT. This system analyzes email content using multi-layered detection algorithms including keyword analysis, domain verification, and URL risk assessment to identify potential phishing threats.

## Team Members

- Ho Winthrop (2500940)
- Ho Shang Jay (2500526)
- Mohamed Raihan Bin Ismail (2503274)
- Matthew Dyason (2500503)
- Leticia Linus Jeraled (2501114)

**Team:** LAB-P5-7
**Course:** INF1002 Programming Fundamentals

---

## Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Deployment](#deployment)
  - [Vercel Deployment](#vercel-deployment)
- [Detection Algorithm](#detection-algorithm)
- [API Endpoints](#api-endpoints)
- [Dependencies](#dependencies)
- [Testing](#testing)
- [License](#license)

---

## Features

### Core Detection Capabilities

- **Multi-Component Analysis System**
  - Keyword-based detection with position-weighted scoring
  - Domain verification with typosquatting detection using Levenshtein distance
  - Comprehensive URL risk assessment with WHOIS integration
  - Component-level score capping to prevent false positives

- **File Format Support**
  - Accepts `.txt` plain text email files
  - Accepts `.eml` structured email files
  - Robust email parsing for multiple formats

- **Risk Scoring System**
  - 5-tier risk assessment: VERY HIGH, HIGH, MEDIUM, LOW, VERY LOW
  - Configurable thresholds via environment variables
  - Domain score cap: 5 points
  - URL score cap: 6 points
  - Keyword score cap: 15 points
  - Total possible score: 26 points

- **Web Interface**
  - User-friendly Flask-based web application
  - Real-time email analysis with instant results
  - Optional email reporting for analysis results
  - Responsive Bootstrap design with modern UI/UX
  - Performance metrics (runtime tracking)

- **Admin Dashboard**
  - Protected admin panel with authentication
  - Real-time analytics and statistics
  - Visual data representation with Chart.js
  - Email classification distribution (pie chart)
  - Top 5 suspicious keywords frequency analysis (bar chart)
  - Auto-refresh functionality (30-second intervals)

- **Data Persistence & Logging**
  - Automatic storage of analysis results in `dataset/safe_keep/`
  - Timestamped file naming for historical tracking
  - Comprehensive logging system using Python's logging module
  - Logs stored in `log/` directory with rotation

### Advanced Features

- **Intelligent Keyword Detection**
  - Position-based scoring:
    - Subject keywords: 3 points each
    - Early body keywords (first 100 words): 2 points each
    - Remaining body keywords: 1 point each
  - CSV keyword database with lemmatization support
  - Regex word boundary matching for accurate detection
  - Organized keyword display by location

- **Domain Analysis**
  - Safe domain whitelist validation from ham email dataset
  - Typosquatting detection using Levenshtein distance algorithm
  - Configurable similarity threshold (default: 4)
  - Robust email extraction from multiple formats

- **URL Risk Assessment**
  - Domain age verification (flags domains < 30 days old)
  - WHOIS data analysis with retry mechanism
  - IP address detection in URLs
  - HTTPS/HTTP protocol verification
  - URL length analysis (>75 characters flagged)
  - Subdirectory count analysis (>3 flagged)
  - Special character detection (@ symbol obfuscation)
  - Domain resolution validation

---

## System Architecture

### Backend Components

#### 1. **website.py** - Flask Web Application (Main Entry Point)
The main application server that orchestrates all detection components.

**Key Functions:**
- `upload_file()`: Handles email file uploads, orchestrates analysis, sends reports
- `admin_login_json()`: Processes admin authentication
- `admin_page()`: Serves admin dashboard
- `parse_stored_emails()`: Extracts statistics from archived data
- `dashboard_data()`: Provides API endpoint for dashboard analytics
- `organize_keywords_by_category()`: Groups keywords by detection location

**Features:**
- Multi-component integration (keywords, domain, URL analysis)
- Component-level score capping
- Enhanced risk messaging for safe domains with suspicious content
- Session management for admin authentication
- Email reporting via SMTP (Gmail)
- Runtime measurement and logging

#### 2. **email_manage.py** - Email Parsing Engine
Extracts components from email files in multiple formats.

**Key Functions:**
- `parse_email_file(email_content)`: Parses .eml and plain text formats

**Capabilities:**
- Handles multipart MIME messages
- Extracts title (From), subject, and body
- UTF-8 decoding with error handling
- Supports structured and unstructured email formats

#### 3. **suspiciouswords.py** - Keyword Detection System
Analyzes email content for suspicious keywords with position-based scoring.

**Key Functions:**
- `consolidate_csv_keywords()`: Merges keyword sources into unified dataset
- `load_keywords(filepath)`: Loads keywords from CSV files
- `detection_subject(subject)`: Analyzes email subject (3 points per keyword)
- `detection_body(body)`: Analyzes email body with early/late detection
- `classify_email(subject, body)`: Returns tuple list of (location, keyword) and suspicion score

**Features:**
- CSV-based keyword management
- Position-aware scoring (subject > early body > remaining body)
- Regex word boundary matching
- Environment-configurable scoring weights
- Lemmatized keyword support

#### 4. **domainchecker.py** - Domain Verification System
Validates sender domains and detects typosquatting attempts.

**Key Functions:**
- `distance_check(domain1, domain2)`: Calculates Levenshtein distance
- `email_titlecheck(email_title)`: Robust email extraction from title with fallback logic
- `domaincheck(email_title, safe_domains, threshold)`: Performs domain analysis

**Features:**
- Safe domain whitelist verification from ham dataset
- Typosquatting detection with configurable threshold
- Similarity scoring for suspicious domains
- Improved email extraction (supports bracketed and non-bracketed formats)

#### 5. **suspiciousurl.py** - URL Risk Assessment Engine
Performs comprehensive URL analysis using multiple risk factors.

**Key Functions:**
- `extract_urls(email_body)`: Extracts all URLs from email content
- `assessing_risk_scores(email_body)`: Analyzes URLs and returns risk data

**Risk Factors:**
- Domain age analysis (<30 days: HIGH, 30-120 days: MEDIUM, 120-365 days: LOW)
- WHOIS data verification with retry mechanism (max 3 retries)
- IP address detection in URLs
- HTTPS/HTTP protocol checking
- URL length analysis (>75 characters flagged)
- Subdirectory count (>3 flagged)
- '@' symbol detection for obfuscation
- Domain resolution check

#### 6. **datas.py** - Domain Database Management
Extracts and maintains safe domain database from ham email dataset.

**Key Functions:**
- `load_data(directory, label)`: Loads emails from directory
- `list_of_domains(text)`: Extracts email domains from text

**Outputs:**
- `unique_from_emails`: Set of safe domains for validation

#### 7. **userdatastore.py** - Data Persistence Layer
Stores email analysis results for historical tracking and admin dashboard.

**Key Functions:**
- `storeDatainTxt(classification, keywords, total_score, EmailDomainMsg, email_text, url_reason_pairs, number_of_urls)`: Saves analysis to timestamped file

**Features:**
- Timestamped file naming (format: `email_data_YYYYMMDD_HHMMSS.txt`)
- Structured data format with classification, keywords, scores, and email content
- Error handling and status reporting

#### 8. **logger.py** - Logging System
Centralized logging configuration and functions.

**Key Functions:**
- `setup_logging()`: Configures logging with file rotation
- `log_analysis()`: Logs detailed analysis results
- `log_admin_login_success()`: Logs successful admin authentication
- `log_admin_login_failure()`: Logs failed login attempts
- `log_admin_logout()`: Logs admin logout
- `log_email_sent()`: Logs successful email report delivery
- `log_email_failed()`: Logs email sending failures
- `log_data_storage_success()`: Logs successful data storage

**Features:**
- Daily log rotation
- 30-day log retention
- Comprehensive analysis logging with performance metrics
- Security event logging

#### 9. **keyword_scrape_web.py** - Web Keyword Scraper
Scrapes spam keywords from external sources to update detection database.

**Key Functions:**
- `get_spam_words()`: Scrapes keywords from configured URL
- `save_csv(words, filename)`: Saves keywords to CSV

**Source:** Configurable via `SPAM_SOURCE_URL` environment variable

### Frontend Components

#### 1. **website/index.html** - Main User Interface
Bootstrap-based responsive landing page for email analysis.

**Sections:**
- Hero section with application description
- File upload area with file preview
- Analysis results display with color-coded risk levels
- Domain verification results
- URL analysis details with individual URL breakdown
- Keyword detection results (organized by location)
- Optional email report delivery form

**Features:**
- File type validation (accept=".eml,.txt,text/plain")
- Real-time file content preview
- Color-coded risk levels (green to red gradient)
- Responsive design for mobile/tablet
- Modern gradient-based styling

#### 2. **website/adminPage.html** - Admin Dashboard
Protected analytics dashboard for monitoring system performance.

**Sections:**
- Safe vs. Phishing email statistics cards
- Pie chart for email distribution
- Bar chart for top 5 suspicious keywords
- Navigation with logout functionality

**Features:**
- Chart.js integration for data visualization
- Auto-refresh functionality (30-second intervals)
- Session-based authentication
- Responsive dashboard layout

#### 3. **website/css/styles.css** - Main Stylesheet
Modern gradient-based design system for user interface.

**Design Features:**
- CSS custom properties for theming
- Gradient backgrounds (purple to pink)
- Card-based layouts with glassmorphism effects
- Smooth animations and transitions
- Responsive breakpoints
- Modern button designs with hover effects

#### 4. **website/css/styles2.css** - Admin Dashboard Stylesheet
Specialized styling for admin analytics interface.

**Design Features:**
- Stat card designs with shadows
- Chart containers with proper spacing
- Dashboard grid layouts

#### 5. **website/js/script.js** - Frontend JavaScript
Handles file preview, admin authentication, and dashboard updates.

**Key Functions:**
- `previewFile()`: Displays uploaded file content
- `adminLoginPrompt()`: Handles admin login flow with JavaScript prompt
- `fetchDashboardData()`: Retrieves analytics data from API
- `updateDashboard(data)`: Updates charts and statistics
- `initializePieChart()`: Creates email distribution chart
- `initializeBarChart()`: Creates keyword frequency chart

---

## Project Structure

```
INF1002-P5-7-Project/
│
├── website.py                    # Main Flask application
├── email_manage.py               # Email parsing engine
├── suspiciouswords.py            # Keyword detection system
├── domainchecker.py              # Domain verification module
├── suspiciousurl.py              # URL risk assessment engine
├── datas.py                      # Domain database management
├── userdatastore.py              # Data persistence layer
├── logger.py                     # Centralized logging system
├── keyword_scrape_web.py         # Web keyword scraper
│
├── website/                      # Frontend files
│   ├── index.html                # Main user interface
│   ├── adminPage.html            # Admin dashboard
│   ├── css/
│   │   └── styles.css            # Stylesheet
│   └── js/
│       └── script.js             # Frontend JavaScript
│
├── dataset/                      # Email datasets
│   └── kaggle/
│       ├── ham/                  # Legitimate emails
│       └── spam_2/               # Spam emails
│
├── keywords/                     # Keyword databases
│   ├── consolidate_keywords.csv  # Unified keyword list
│   ├── lemmatized_keywords.csv   # Processed keywords
│   ├── lemmatizer.py             # Keyword lemmatization script
│   └── raw_data/                 # Source keyword files
│       ├── phishing_keywords.csv
│       └── spam_words.csv
│
├── .env.example                  # Environment configuration template
├── .gitignore                    # Git ignore rules
├── requirements.txt              # Python dependencies
├── README.md                     # Project documentation
└── CLAUDE.md                     # Claude Code instructions
```

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Virtual environment (recommended)
- Git

### Step-by-Step Installation

1. **Clone the Repository**
```bash
git clone https://github.com/winthrop1/INF1002-P5-7-Project.git
cd INF1002-P5-7-Project
```

2. **Create Virtual Environment** (Recommended)
```bash
python3 -m venv .venv
```

3. **Activate Virtual Environment**
```bash
# macOS/Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

4. **Install Dependencies**
```bash
pip install -r requirements.txt
```

5. **Configure Environment Variables**
```bash
cp .env.example .env
```
Edit `.env` file with your configuration (see [Configuration](#configuration) section)

6. **Download NLTK Data** (for lemmatization features)
```python
python -c "import nltk; nltk.download('wordnet'); nltk.download('omw-1.4')"
```

7. **Verify Installation**
```bash
python website.py
```
Application should start on `http://127.0.0.1:5000`

---

## Configuration

### Environment Variables

The system uses a `.env` file for configuration. Copy `.env.example` to `.env` and customize:

#### Flask Configuration
```env
TEMPLATE_FOLDER=website
SECRET_KEY=your-secret-key-here
```

#### Admin Credentials
```env
ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD=your_secure_password
```

#### Dataset Paths
```env
HAM_DATASET_DIR=dataset/kaggle/ham          # Directory for legitimate email samples (2800+ files)
SPAM_DATASET_DIR=dataset/kaggle/spam_2      # Directory for spam/phishing samples (1400+ files)
```

#### Email Reporting (Optional)
```env
EMAIL_ADDRESS=your-email@gmail.com
EMAIL_KEY=your-app-specific-password
```
**Note:** For Gmail, you need to generate an App Password. Visit [Google App Passwords](https://myaccount.google.com/apppasswords)

#### Keyword Configuration
```env
KEYWORDS_FOLDER=keywords
KEYWORDS_CONSOLIDATE_FILE=keywords/lemmatized_keywords.csv
KEYWORDS_RAW_FOLDER=keywords/raw_data
```

#### Scoring Weights

**Domain Analysis:**
```env
DOMAIN_SUSPICION_SCORE=2        # Score for unrecognized domain
DOMAIN_SIMILARITY_THRESHOLD=4   # Levenshtein distance threshold
```

**URL Analysis:**
```env
HIGH_DOMAIN_SCORE=3              # Domain < 30 days old
MEDIUM_DOMAIN_SCORE=2            # Domain 30-120 days old
LOW_DOMAIN_SCORE=1               # Domain 120-365 days old
HIGH_DOMAIN_EXPIRY_SCORE=2       # Expiring within 6 months
LOW_DOMAIN_EXPIRY_SCORE=1        # Expiring within 1 year
DOMAIN_UPDATE_SCORE=1            # Recently updated domain
IP_ADDRESS_SCORE=2               # IP address in URL
NO_HTTPS_SCORE=2                 # No HTTPS
HTTP_SCORE=1                     # HTTP instead of HTTPS
LONG_URL_SCORE=1                 # URL > 75 characters
AT_SYMBOL_SCORE=2                # '@' symbol in URL
SUBDIR_COUNT_SCORE=1             # > 3 subdirectories
UNRESOLVED_DOMAIN_SCORE=3        # Domain doesn't resolve
```

**Keyword Analysis:**
```env
SUBJECT_KEYWORD_SCORE=3          # Keyword in subject
EARLY_BODY_WORD_COUNT=100        # First N words = "early body"
EARLY_BODY_KEYWORD_SCORE=2       # Keyword in early body
BODY_KEYWORD_SCORE=1             # Keyword in remaining body
```

**Score Caps:**
```env
MAX_DOMAIN_SCORE=5               # Cap for domain score
MAX_URL_SCORE=6                  # Cap for URL score
MAX_KEYWORD_SCORE=15             # Cap for keyword score
```

**Risk Thresholds:**
```env
VERY_HIGH_RISK_THRESHOLD=16      # ≥16 points = VERY HIGH
HIGH_RISK_THRESHOLD=12           # 12-15 points = HIGH
MEDIUM_RISK_THRESHOLD=8          # 8-11 points = MEDIUM
LOW_RISK_THRESHOLD=4             # 4-7 points = LOW
                                 # <4 points = VERY LOW

PHISHING_SCORE=8                 # Threshold to classify as phishing
```

#### Web Scraping Configuration
```env
SPAM_SOURCE_URL=https://www.activecampaign.com/blog/spam-words
SPAM_WORDS_PATH=keywords/spam_words.txt
```

---

## Usage

### Running the Web Application

1. **Start the Flask Server**
```bash
python website.py
```

2. **Access the Application**
   - Open browser to: `http://127.0.0.1:5000`
   - Application runs in debug mode for development

3. **Analyze an Email**
   - Click "Choose file" or drag email file to upload area
   - Supported formats: `.txt`, `.eml`
   - Email content preview loads automatically
   - (Optional) Enter your email address to receive analysis report
   - Click "Analyze Email" button
   - View comprehensive results including:
     - Risk level classification (VERY HIGH to VERY LOW)
     - Total risk score (out of 26)
     - Component scores (domain, URL, keywords)
     - Domain verification results
     - URL analysis with individual URL breakdown
     - Detected suspicious keywords (organized by location)
     - Runtime performance metrics

### Accessing Admin Dashboard

1. **Login to Admin Panel**
   - Click "Admin" button in navigation bar
   - Enter admin credentials (from `.env` file)
   - JavaScript prompt will appear
   - Click OK to authenticate

2. **View Analytics**
   - Safe vs. Phishing email counts
   - Total emails analyzed
   - Email distribution pie chart
   - Top 5 suspicious keywords bar chart
   - Auto-refreshes every 30 seconds

3. **Logout**
   - Click "Logout" in navigation bar
   - Returns to main page

### Command-Line Tools

#### Update Keyword Database from Web
```bash
python keyword_scrape_web.py
```
Scrapes latest spam keywords from configured URL and saves to CSV

#### Lemmatize Keywords
```bash
python keywords/lemmatizer.py
```
Processes keywords to base forms for better detection

#### Test Email Parsing
```bash
python email_manage.py
```
Tests email parsing functionality on test file

#### Extract Safe Domains
```bash
python datas.py
```
Builds safe domain database from ham email dataset

---

## Deployment

### Vercel Deployment

This application is configured for deployment on Vercel's serverless platform. The deployment automatically handles scaling and provides a production-ready environment.

#### Quick Deploy to Vercel

1. **Prerequisites**
   - GitHub account
   - Vercel account (free tier available at [vercel.com](https://vercel.com))
   - Project pushed to GitHub repository

2. **Deploy via Vercel Dashboard**

   **Step 1: Import Project**
   ```
   1. Visit https://vercel.com/new
   2. Click "Import Git Repository"
   3. Select your GitHub repository
   4. Click "Import"
   ```

   **Step 2: Configure Build Settings**
   ```
   Framework Preset: Other
   Build Command: (leave empty)
   Output Directory: (leave empty)
   Install Command: pip install -r requirements.txt
   ```

   **Step 3: Add Environment Variables**

   In the Vercel dashboard, go to **Settings > Environment Variables** and add:

   **Required Variables:**
   ```env
   SECRET_KEY=<generate-a-secure-random-key>
   ADMIN_USERNAME=<your-admin-username>
   ADMIN_PASSWORD=<your-admin-password>
   ```

   **Optional Variables (for email reporting):**
   ```env
   EMAIL_ADDRESS=<your-gmail@gmail.com>
   EMAIL_KEY=<your-gmail-app-password>
   ```

   **All other environment variables** from `.env.example` can be added with their default values.

   **Step 4: Deploy**
   ```
   Click "Deploy"
   Wait for deployment to complete (2-3 minutes)
   Visit your live URL: https://your-project-name.vercel.app
   ```

3. **Deploy via Vercel CLI** (Alternative)

   ```bash
   # Install Vercel CLI
   npm install -g vercel

   # Login to Vercel
   vercel login

   # Deploy from project directory
   cd INF1002-P5-7-Project
   vercel

   # Follow prompts to configure deployment
   # Add environment variables when prompted

   # Deploy to production
   vercel --prod
   ```

4. **Important Notes for Vercel Deployment**

   **Serverless Mode Behavior:**
   - ✅ **Works:** All email analysis features (keywords, domain check, URL analysis)
   - ✅ **Works:** Email reporting via SMTP
   - ✅ **Works:** Admin dashboard with dummy data
   - ⚠️ **Limited:** File storage disabled (analysis results not persisted)
   - ⚠️ **Limited:** Admin dashboard shows dummy/demo data

   **Environment Detection:**
   - The application automatically detects Vercel environment via `VERCEL=true` env variable
   - In serverless mode, file storage is disabled and dummy data is used for charts
   - All core phishing detection features remain fully functional

   **Testing Serverless Mode Locally:**
   ```bash
   # Add to your .env file
   USE_DUMMY_DATA=true

   # Run the application
   python website.py
   ```

5. **Switching Between Local and Serverless Data**

   The application automatically switches between real data (local) and dummy data (Vercel) based on environment:

   **Local Development (Real Data):**
   ```bash
   # .env file - no special configuration needed
   # Stores analysis results in dataset/safe_keep/
   # Dashboard shows real analytics
   python website.py
   ```

   **Vercel Production (Dummy Data):**
   ```bash
   # Vercel automatically sets VERCEL=true
   # File storage disabled
   # Dashboard shows demo statistics:
   #   - 42 Safe emails
   #   - 18 Phishing emails
   #   - Top keywords: urgent, verify, account, click, suspended
   ```

   **Force Dummy Data Locally (Testing):**
   ```env
   # Add to .env file
   USE_DUMMY_DATA=true
   ```

6. **Post-Deployment Configuration**

   **Custom Domain (Optional):**
   ```
   Vercel Dashboard > Domains > Add Domain
   Follow DNS configuration instructions
   ```

   **Environment Variables Update:**
   ```
   Vercel Dashboard > Settings > Environment Variables
   Edit any variable and redeploy
   ```

   **Monitoring:**
   ```
   Vercel Dashboard > Deployments > View Logs
   Monitor function invocations and errors
   ```

7. **Upgrading to Full Persistence (Future)**

   To enable full data persistence on Vercel, consider:
   - **Database Integration:** Add Vercel Postgres or MongoDB Atlas
   - **External Storage:** Use AWS S3 or Vercel Blob for file storage
   - **Modify Code:** Update `userdatastore.py` and `parse_stored_emails()` to use database

   This is not required for basic demonstration but useful for production deployment.

---

## Detection Algorithm

### Multi-Component Risk Scoring

The system uses a sophisticated multi-layered approach with component-level capping:

```
Total Score = min(Domain Score, 5) + min(URL Score, 6) + min(Keyword Score, 15)
Maximum Possible Score = 26 points
```

#### 1. Keyword Detection (`suspiciouswords.py`)

**Position-Based Scoring:**
```python
# Subject keywords (highest weight)
if keyword in subject:
    score += SUBJECT_KEYWORD_SCORE  # Default: 3

# Early body keywords (first 100 words)
elif keyword in first_100_words_of_body:
    score += EARLY_BODY_KEYWORD_SCORE  # Default: 2

# Remaining body keywords (lowest weight)
elif keyword in remaining_body:
    score += BODY_KEYWORD_SCORE  # Default: 1

# Maximum capped at 15 points
```

**Detection Features:**
- Regex word boundary matching (`\b` anchors)
- Case-insensitive matching
- CSV-based keyword database with lemmatization
- Position-aware scoring (subject > early > late)
- Returns tuple list: `[(location, keyword), ...]`

#### 2. Domain Analysis (`domainchecker.py`)

**Typosquatting Detection:**
```python
# Extract email from title
email = email_titlecheck(email_title)  # Handles multiple formats
domain = "@" + email.split('@')[1]

# Check against safe domain whitelist
if domain not in safe_domains:
    score += DOMAIN_SUSPICION_SCORE  # Default: 2

# Levenshtein distance calculation
domain_distance = levenshtein_distance(sender_domain, safe_domain)

if domain_distance <= THRESHOLD:  # Default: 4
    score += domain_distance
    # Example: "microsft.com" vs "microsoft.com" = 1 character change

# Maximum capped at 5 points
```

**Analysis Features:**
- Levenshtein distance algorithm for similarity
- Safe domain whitelist from ham dataset
- Configurable similarity threshold
- Typosquatting alerts with similarity score

#### 3. URL Risk Assessment (`suspiciousurl.py`)

**Multi-Factor Analysis:**
```python
# Domain age check
if domain_age < 30_days:
    score += HIGH_DOMAIN_SCORE  # Default: 3
elif domain_age < 120_days:
    score += MEDIUM_DOMAIN_SCORE  # Default: 2
elif domain_age < 365_days:
    score += LOW_DOMAIN_SCORE  # Default: 1

# Security checks
if ip_address_in_url:
    score += IP_ADDRESS_SCORE  # Default: 2

if not uses_https:
    score += NO_HTTPS_SCORE  # Default: 2

# Structural checks
if url_length > 75:
    score += LONG_URL_SCORE  # Default: 1

if '@' in url:
    score += AT_SYMBOL_SCORE  # Default: 2

if subdirectory_count > 3:
    score += SUBDIR_COUNT_SCORE  # Default: 1

# Domain resolution
if not can_resolve_domain:
    score += UNRESOLVED_DOMAIN_SCORE  # Default: 3

# Maximum capped at 6 points
```

**Analysis Features:**
- WHOIS data integration with retry mechanism
- Domain age and expiry verification
- Protocol analysis (HTTPS/HTTP)
- Structural analysis (length, subdirectories)
- Obfuscation detection (@ symbol, IP addresses)
- Returns list of dictionaries with URL and reasons

#### 4. Final Risk Calculation (`website.py`)

**Component-Level Capping:**
```python
# Apply individual caps to prevent single component from dominating
domain_capped = min(domain_score, MAX_DOMAIN_SCORE)      # Cap: 5
url_capped = min(url_score, MAX_URL_SCORE)               # Cap: 6
keywords_capped = min(keywords_score, MAX_KEYWORD_SCORE) # Cap: 15

total_risk_score = domain_capped + url_capped + keywords_capped
```

**Risk Level Assignment:**
```python
if total_risk_score >= 16:
    risk_level = "VERY HIGH"  # Critical threat
elif total_risk_score >= 12:
    risk_level = "HIGH"       # High threat
elif total_risk_score >= 8:
    risk_level = "MEDIUM"     # Moderate threat
elif total_risk_score >= 4:
    risk_level = "LOW"        # Low threat
else:
    risk_level = "VERY LOW"   # Minimal threat
```

**Final Classification:**
```python
# Uses configurable PHISHING_SCORE threshold (default: 8)
classification = "Safe" if total_risk_score <= PHISHING_SCORE else "Phishing"
```

### Algorithm Flow Diagram

```
Email Upload (.txt or .eml)
           ↓
    Parse Email (email_manage.py)
           ↓
Extract: From/Title, Subject, Body
           ↓
    ┌──────────────┬────────────────┬──────────────┐
    │              │                │              │
    │  Keyword     │   Domain       │     URL      │
    │  Detection   │   Analysis     │   Analysis   │
    │              │                │              │
    │ suspicious   │  domain        │  suspicious  │
    │ words.py     │  checker.py    │  url.py      │
    │              │                │              │
    │ Score: 0-15  │  Score: 0-5    │  Score: 0-6  │
    │ (capped)     │  (capped)      │  (capped)    │
    └──────────────┴────────────────┴──────────────┘
         │              │                │
         └──────────────┴────────────────┘
                       ↓
              Sum Component Scores
                       ↓
           Total Score: 0-26 points
                       ↓
          Assign Risk Level (VERY HIGH to VERY LOW)
                       ↓
         Classify (Safe ≤8 / Phishing >8)
                       ↓
              Display Results
                       ↓
          Store Data + Send Email Report (optional)
```

---

## API Endpoints

### User Endpoints

#### `GET /` - Main Application Page
Returns the main email analysis interface (index.html).

**Response:**
- HTML page with file upload form

#### `POST /` - Analyze Email
Analyzes uploaded email file and returns results.

**Request:**
- Method: POST
- Content-Type: multipart/form-data
- Parameters:
  - `emailfile`: File upload (.txt or .eml) - Required
  - `userEmail`: User email for report - Optional

**Response:**
- HTML page with analysis results including:
  - Classification (Safe/Phishing)
  - Risk level (VERY HIGH to VERY LOW)
  - Total risk score and component scores
  - Keywords found (organized by location)
  - URL analysis with reasons
  - Domain verification results
  - Email notification status (if email provided)
  - Data storage confirmation

### Admin Endpoints

#### `POST /admin-login-json` - Admin Authentication
Authenticates admin credentials via JSON.

**Request:**
```json
{
  "username": "admin_username",
  "password": "admin_password"
}
```

**Response:**
```json
{
  "success": true
}
```
or
```json
{
  "success": false,
  "error": "Invalid email or password."
}
```

#### `GET /admin` - Admin Dashboard
Returns admin dashboard page. Requires authentication (session).

**Response:**
- HTML page (adminPage.html) if authenticated
- Redirect to main page if not authenticated

#### `GET /api/dashboard-data` - Dashboard Analytics
Provides analytics data for admin dashboard. Requires authentication.

**Response:**
```json
{
  "safe_count": 42,
  "phishing_count": 18,
  "total_emails": 60,
  "top_keywords": [
    {"keyword": "urgent", "count": 15},
    {"keyword": "verify", "count": 12},
    {"keyword": "account", "count": 10},
    {"keyword": "suspended", "count": 8},
    {"keyword": "click", "count": 7}
  ]
}
```

**Error Response:**
```json
{
  "error": "Unauthorized"
}
```
Status Code: 401

#### `GET /logout` - Logout
Clears admin session and redirects to main page.

**Response:**
- Redirect to main page (/)

---

## Dependencies

### Core Python Packages

```txt
flask==3.1.2               # Web framework for application server
requests==2.32.5           # HTTP library for web scraping
lxml==6.0.1                # HTML/XML processing for parsing
python-dotenv==1.1.1       # Environment variable management
pandas>=1.5.0              # Data manipulation for domain analysis
validators                 # URL/domain validation library
python-whois               # Domain WHOIS lookup integration
free-email-domains         # Free email domain detection
nltk                       # Natural language processing (lemmatization)
```

### Frontend Libraries (CDN)

- **Bootstrap 5.3.0** - Responsive CSS framework
- **Font Awesome 6.3.0** - Icon library
- **Chart.js 2.8.0** - Data visualization for admin dashboard

### Standard Library Modules

- `re` - Regular expressions for text processing
- `os` - File system operations
- `csv` - CSV file handling
- `glob` - File pattern matching
- `smtplib` - Email sending (SMTP)
- `email` - Email parsing and message creation
- `datetime` - Timestamp generation
- `collections` - Counter for frequency analysis
- `socket` - Network operations
- `time` - Performance measurement
- `logging` - Application logging

### Installation

```bash
pip install -r requirements.txt
```

---

## Testing

### Test Email Datasets

Located in `dataset/testing/` directory:

**Ham (Legitimate) Emails:**
- `dataset/testing/ham/` - 12 legitimate email files
- Used for safe domain extraction via `datas.py`
- Used for false positive testing
- Helps build the trusted domain whitelist

**Spam/Phishing Emails:**
- `dataset/testing/spam/` - 12 phishing/spam email files
- Used for detection accuracy testing
- Used for keyword extraction
- Provides real-world phishing examples

### Manual Testing

#### Test Full Application
```bash
python website.py
```
Then upload test files through web interface at `http://127.0.0.1:5000`

#### Test Individual Components

**Email Parsing:**
```bash
python email_manage.py
```

**Domain Extraction:**
```bash
python datas.py
```

**Keyword Scraping:**
```bash
python keyword_scrape_web.py
```

**Keyword Lemmatization:**
```bash
python keywords/lemmatizer.py
```

#### Test with Python Script
```python
from email_manage import parse_email_file
from suspiciouswords import classify_email
from domainchecker import domaincheck
from suspiciousurl import assessing_risk_scores

# Load test email
with open('dataset/testing/spam/spam_1.txt', 'r') as f:
    email_content = f.read()

# Parse email
title, subject, body = parse_email_file(email_content)

# Run detection components
keywords, keywords_score = classify_email(subject, body)
domain_msg, distance_msg, domain_score = domaincheck(title)
reasons, url_score, url_pairs, num_urls, num_domains = assessing_risk_scores(body)

# Calculate total with caps
domain_capped = min(domain_score, 5)
url_capped = min(url_score, 6)
keywords_capped = min(keywords_score, 15)

total_score = domain_capped + url_capped + keywords_capped

print(f"Total Risk Score: {total_score}/26")
print(f"Classification: {'Safe' if total_score <= 8 else 'Phishing'}")
```

### Web Interface Testing

1. Start the application: `python website.py`
2. Navigate to `http://127.0.0.1:5000`
3. Upload test files from `dataset/testing/`
4. Verify risk scores and classifications
5. Test email reporting functionality (optional)
6. Test admin dashboard:
   - Click "Admin" button
   - Login with credentials from `.env`
   - Verify statistics and charts
   - Check auto-refresh functionality
   - Logout and verify session cleared
7. Verify data storage in `dataset/safe_keep/`
8. Check logs in `log/phishing_detector.log`

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Copyright

Copyright (c) 2025 Ho Winthrop, Ho Shang Jay, Mohamed Raihan Bin Ismail, Matthew Dyason, Leticia Linus Jeraled

Permission is granted to use, modify, and distribute this software under the terms of the MIT License.
