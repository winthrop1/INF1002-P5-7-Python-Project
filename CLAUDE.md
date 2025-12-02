# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a phishing email detection system that uses a multi-component rule-based approach to classify emails as safe or phishing. The system consists of three independent detection modules that run in parallel, each contributing to a final risk score with component-level caps to prevent any single module from dominating the assessment.

## Running the Application

**Local Development:**
```bash
python website.py
```
The application will be available at `http://127.0.0.1:5000`.

**Vercel Deployment:**
- Application is deployed as a serverless function via `api/index.py`
- Vercel automatically sets `VERCEL=true` environment variable
- See [Deployment Configuration](#deployment-configuration) section below

**Test individual modules:**
```bash
# Test email parsing
python email_manage.py

# Test keyword consolidation
python suspiciouswords.py

# Extract safe domains from ham dataset
python datas.py

# Scrape spam keywords from web
python keyword_scrape_web.py
```

## Environment Configuration

The application requires a `.env` file (copy from `.env.example`). All scoring weights, thresholds, and configuration are controlled via environment variables, not hardcoded. Key categories:

- **Scoring weights**: `SUBJECT_KEYWORD_SCORE`, `DOMAIN_SUSPICION_SCORE`, `HIGH_DOMAIN_SCORE`, etc.
- **Component caps**: `MAX_DOMAIN_SCORE=5`, `MAX_URL_SCORE=6`, `MAX_KEYWORD_SCORE=15` (total max: 26 points)
- **Risk thresholds**: `VERY_HIGH_RISK_THRESHOLD=16`, `HIGH_RISK_THRESHOLD=12`, etc.
- **Phishing classification**: `PHISHING_SCORE=8` (threshold to classify as phishing)
- **Email reporting**: `EMAIL_ADDRESS`, `EMAIL_KEY` (Gmail app password)
- **Admin credentials**: `ADMIN_USERNAME`, `ADMIN_PASSWORD`

## System Architecture

### Three-Pillar Detection System

The system uses three independent detection modules that run in parallel in `website.py`:

1. **Keyword Detection** (`suspiciouswords.py`):
   - Position-based scoring: subject (3 pts) > early body (2 pts) > remaining body (1 pt)
   - Early body defined as first 100 words (configurable via `EARLY_BODY_WORD_COUNT`)
   - Uses regex word boundaries (`\b`) to match whole words only
   - Keywords loaded from `keywords/lemmatized_keywords.csv`
   - Returns: `(keywords_list, keywords_score)` where keywords_list contains tuples: `[(location, keyword), ...]`

2. **Domain Verification** (`domainchecker.py`):
   - Extracts sender email from "From" field using `email_titlecheck()`
   - Checks against safe domain whitelist from `datas.py` (extracted from ham dataset)
   - Also checks against free email domains from `free_email_domains` library
   - Typosquatting detection using Levenshtein distance algorithm (`distance_check()`)
   - Threshold configurable via `DOMAIN_SIMILARITY_THRESHOLD` (default: 4)
   - Returns: `(EmailDomainMsg, DistanceCheckMsg, domain_score)`

3. **URL Risk Assessment** (`suspiciousurl.py`):
   - Extracts URLs via regex: `r"https?://[^\s]+"`
   - Limits analysis to first 6 unique domains for performance
   - For each URL, checks:
     - Domain age via WHOIS (with retry mechanism and LRU caching)
     - HTTPS/HTTP protocol
     - IP address in URL (including obfuscated formats)
     - URL length and structure
     - Domain resolution
   - Returns: `(reasons, url_score, url_reason_pairs, number_of_urls, number_of_unique_domains)`

### Score Calculation Flow

In `website.py`, the `upload_file()` function orchestrates all three modules:

```python
# Run three detection modules independently
domain_msg, distance_msg, domain_score = domaincheck(email_title)
reasons, url_score, url_pairs, num_urls, num_domains = assessing_risk_scores(email_body)
keywords, keywords_score = classify_email(email_subject, email_body)

# Apply component-level caps (critical for fair assessment)
domain_capped = min(domain_score, MAX_DOMAIN_SCORE)      # Cap at 5
url_capped = min(url_score, MAX_URL_SCORE)               # Cap at 6
keywords_capped = min(keywords_score, MAX_KEYWORD_SCORE) # Cap at 15

# Calculate total risk score (max: 26)
total_risk_score = domain_capped + url_capped + keywords_capped

# Assign risk level and classification
if total_risk_score >= VERY_HIGH_RISK_THRESHOLD: risk_level = "VERY HIGH"
elif total_risk_score >= HIGH_RISK_THRESHOLD: risk_level = "HIGH"
# ... etc

classification = "Safe" if total_risk_score <= PHISHING_SCORE else "Phishing"
```

### Email Parsing

`email_manage.py` handles two formats:
- **Structured .eml files**: Uses Python's `email.message_from_string()` to parse headers and multipart bodies
- **Plain text files**: Extracts subject line via regex and treats rest as body

Returns: `(title, subject, body)` where title is constructed from sender info.

### Data Flow

1. User uploads email file → `website.py:upload_file()`
2. File decoded and parsed → `email_manage.py:parse_email_file()`
3. Three detection modules run in parallel → returns scores and messages
4. Component-level caps applied → prevents score domination
5. Risk level calculated and classification determined
6. Results stored → `userdatastore.py:storeDatainTxt()` in `dataset/safe_keep/`
7. Optional email report sent via SMTP
8. Results logged → `logger.py`
9. Results rendered in `website/index.html`

### Admin Dashboard

The admin dashboard (`website/adminPage.html`) displays analytics:
- Safe vs. Phishing email counts
- Top 5 suspicious keywords (bar chart)
- Email distribution (pie chart)
- Auto-refreshes every 30 seconds

Data comes from parsing all stored analysis files in `dataset/safe_keep/`:
- `parse_stored_emails()` in `website.py` extracts statistics via regex
- API endpoint: `/api/dashboard-data` returns JSON
- Authentication via session (`admin_logged_in` flag)
- Credentials checked against environment variables

### Keyword Management

Keywords are consolidated from multiple CSV sources:
- Raw keyword files in `keywords/raw_data/`
- `consolidate_csv_keywords()` in `suspiciouswords.py` merges and deduplicates
- Lemmatization via `keywords/lemmatizer.py` (requires NLTK)
- Final dataset: `keywords/lemmatized_keywords.csv`

### Safe Domain Database

`datas.py` extracts safe domains from ham emails:
- Loads all files from `HAM_DATASET_DIR` (default: `dataset/kaggle/ham/`)
- Searches for "From:" lines and extracts domains
- Exports `unique_from_emails` set used by `domainchecker.py`

## Important Implementation Details

### Component-Level Score Capping

The capping system is critical to prevent false positives. Without it, a single component could dominate:
- Example: An email with 20 suspicious keywords would score 20+ points even if domain and URLs are safe
- With caps: Keywords capped at 15, leaving room for domain (5) and URL (6) assessment
- Always apply caps **before** summing to total score

### Global Variables in suspiciousurl.py

`suspiciousurl.py` uses global variables `url_suspicion_score` and `reasons` that must be reset at the start of `assessing_risk_scores()`:
```python
def assessing_risk_scores(email_body):
    global url_suspicion_score
    global reasons

    # CRITICAL: Reset globals for each email
    url_suspicion_score = 0
    reasons = []
    # ... rest of function
```

### Keyword Location Tuples

Keywords are returned as tuples containing location information: `[(location, keyword), ...]`
- Locations: `'subject'`, `'early_body'`, `'remaining_body'`
- This format is used for organized display in the UI
- `organize_keywords_by_category()` in `website.py` groups them for display

### URL Domain Deduplication

`assessing_risk_scores()` only analyzes the longest URL per unique domain:
```python
urls_with_unique_domains = {}
for url in urls:
    domain = get_domain_from_url(url)
    if domain not in urls_with_unique_domains or len(url) > len(urls_with_unique_domains[domain]):
        urls_with_unique_domains[domain] = url  # Keep longest URL per domain
```

This prevents performance issues when emails contain many URLs to the same domain.

### Email Title Extraction

`domainchecker.py:email_titlecheck()` handles multiple formats:
- Bracketed: `"John Doe <john@example.com>"`
- Unbracketed: `"john@example.com"`
- With quotes/parentheses: `"(john@example.com)"`

The function strips all common punctuation and extracts the email address.

### WHOIS Caching and Retry

`suspiciousurl.py` implements:
- LRU cache (`@lru_cache(maxsize=1000)`) for WHOIS lookups
- Retry mechanism with exponential backoff (max 3 retries)
- Naive datetime conversion (`make_comparable()`) to handle timezone-aware dates

### Logging System

`logger.py` provides centralized logging:
- Configurable via `ENABLE_LOGGING`, `LOG_LEVEL` environment variables
- Logger name extracted from `LOG_FILE` (removes .log extension)
- Prevents propagation to root logger (`logger.propagate = False`)
- Avoids duplicate handlers
- All analysis events, admin actions, and errors are logged

## File Organization

**Core detection modules:**
- `website.py`: Flask application and orchestration
- `suspiciouswords.py`: Keyword detection
- `domainchecker.py`: Domain verification
- `suspiciousurl.py`: URL risk assessment
- `email_manage.py`: Email parsing

**Supporting modules:**
- `datas.py`: Safe domain extraction
- `userdatastore.py`: Analysis result storage
- `logger.py`: Centralized logging
- `keyword_scrape_web.py`: Web scraping for keywords

**Frontend:**
- `website/index.html`: Main UI
- `website/adminPage.html`: Admin dashboard
- `website/js/script.js`: Frontend JavaScript
- `website/css/styles.css`: Main stylesheet

**Data:**
- `dataset/kaggle/hamEmails/`: Legitimate emails (for safe domain extraction)
- `dataset/testing/spam/`: Spam emails (for testing)
- `dataset/testing/ham/`: Spam emails (for testing)
- `dataset/safe_keep/`: Stored analysis results (timestamped .txt files)
- `keywords/lemmatized_keywords.csv`: Primary keyword database
- `keywords/raw_data/`: Raw keyword sources
- `log/`: Application logs

## Common Modifications

**Adjusting detection sensitivity:**
1. Modify scoring weights in `.env` (e.g., increase `SUBJECT_KEYWORD_SCORE`)
2. Adjust component caps (`MAX_DOMAIN_SCORE`, `MAX_URL_SCORE`, `MAX_KEYWORD_SCORE`)
3. Change risk thresholds (`HIGH_RISK_THRESHOLD`, `PHISHING_SCORE`)

**Adding new keywords:**
1. Add CSV file to `keywords/raw_data/`
2. Run `python suspiciouswords.py` to consolidate
3. Optionally run `python keywords/lemmatizer.py` to lemmatize

**Modifying URL checks:**
Edit functions in `suspiciousurl.py`:
- `having_ip_address()`: IP detection logic
- `https_check()`: Protocol verification
- `url_check()`: Length and structure checks
- `analyze_domain_info()`: WHOIS data analysis

Remember: All functions update global `url_suspicion_score` and `reasons`.

## Testing Notes

- Test emails located in `dataset/testing/spam/` and `dataset/testing/ham/`
- Each analysis result is automatically stored in `dataset/safe_keep/` with timestamp (local mode only)
- Admin dashboard reads from `dataset/safe_keep/` to generate statistics (local mode only)
- Manual testing can be done by uploading files through web interface or running individual modules

## Deployment Configuration

### Vercel Serverless Deployment

The application is configured for deployment on Vercel's serverless platform with automatic environment detection.

#### File Structure for Deployment

**Vercel Entrypoint:**
- `api/index.py`: Serverless function entrypoint that imports and exports the Flask app from `website.py`
- Vercel automatically detects this file and creates a serverless function

**Configuration Files:**
- `vercel.json`: Vercel build and routing configuration
  - Specifies Python runtime via `@vercel/python`
  - Routes static assets (`/css/*`, `/js/*`, `/images/*`) to `website/` folder
  - Routes all other requests to `api/index.py`
  - Sets `VERCEL=true` environment variable automatically

- `.vercelignore`: Excludes unnecessary files from deployment
  - Virtual environments (`.venv`, `venv`)
  - Git files (`.git`)
  - Environment files (`.env`)
  - Log files (`log/`)
  - Large datasets (`dataset/kaggle/`, `dataset/testing/`)
  - Analysis storage (`dataset/safe_keep/`)

#### Environment Detection and Mode Switching

The application automatically detects deployment environment and adjusts behavior:

**Environment Variables for Mode Control:**
```python
# In website.py
is_serverless = os.getenv('VERCEL', '').lower() == 'true' or os.getenv('USE_DUMMY_DATA', '').lower() == 'true'
```

**Serverless Mode (VERCEL=true):**
- File storage disabled: `storeDatainTxt()` is skipped
- Dummy data used for admin dashboard charts via `get_dummy_dashboard_data()`
- All core detection features (keywords, domain, URL) remain fully functional
- Email reporting via SMTP works normally

**Local Mode (default):**
- File storage enabled: Analysis results saved to `dataset/safe_keep/`
- Real data used for admin dashboard from stored analysis files
- All features fully functional

**Testing Serverless Behavior Locally:**
Add to `.env` file:
```env
USE_DUMMY_DATA=true
```

#### Dummy Data for Admin Dashboard

When in serverless mode or no stored files found, `get_dummy_dashboard_data()` returns:
```python
{
    'safe_count': 42,
    'phishing_count': 18,
    'top_keywords': [
        ('urgent', 15),
        ('verify', 12),
        ('account', 10),
        ('click', 8),
        ('suspended', 6)
    ],
    'total_emails': 60
}
```

This allows the admin dashboard to display representative data even without persistent storage.

#### Serverless Limitations and Workarounds

**What Works:**
- ✅ All email analysis (keyword detection, domain checking, URL assessment)
- ✅ Risk scoring and classification
- ✅ Email reporting via SMTP
- ✅ Admin dashboard with dummy/demo data
- ✅ Session-based authentication

**What's Limited:**
- ⚠️ File writes don't persist between function invocations
- ⚠️ Analysis history not stored (use database for persistence)
- ⚠️ Admin dashboard shows dummy data (not real analytics)
- ⚠️ Logs don't persist (use Vercel logs or external logging service)

**Future Upgrades for Full Serverless Functionality:**
1. **Add Database:** Integrate Vercel Postgres or MongoDB Atlas
   - Modify `userdatastore.py` to write to database
   - Update `parse_stored_emails()` to query database
2. **External Logging:** Use logging service (Sentry, LogRocket)
3. **Blob Storage:** Use Vercel Blob or S3 for file persistence

#### Required Environment Variables on Vercel

Configure these in Vercel Dashboard > Settings > Environment Variables:

**Essential:**
```env
SECRET_KEY=<generate-with: python -c "import secrets; print(secrets.token_hex(32))">
ADMIN_USERNAME=<your-admin-username>
ADMIN_PASSWORD=<your-admin-password>
```

**Optional (Email Reporting):**
```env
EMAIL_ADDRESS=<your-gmail@gmail.com>
EMAIL_KEY=<gmail-app-password>
```

**All other variables** from `.env.example` should be added with their default values for proper configuration.

#### Deployment Process

**Via Vercel Dashboard:**
1. Connect GitHub repository
2. Import project
3. Framework preset: Other
4. Add environment variables
5. Deploy

**Via Vercel CLI:**
```bash
npm install -g vercel
vercel login
vercel  # Follow prompts
vercel --prod  # Deploy to production
```

#### Static File Handling

The `vercel.json` routes configuration ensures static assets are served correctly:
- CSS files: `/css/*` → `/website/css/*`
- JavaScript: `/js/*` → `/website/js/*`
- Images: `/images/*` → `/website/images/*`
- Templates: Flask's `template_folder='website'` handles HTML rendering

#### Session Management in Serverless

Flask sessions work in serverless mode because:
- Sessions are cookie-based (not server-side storage)
- `SECRET_KEY` encrypts session cookies
- No persistent storage required for authentication
- Admin login persists across function invocations via encrypted cookies

#### Monitoring and Debugging

**Vercel Dashboard:**
- View function logs: Deployments > Function Logs
- Monitor invocations and errors
- Check build logs for deployment issues

**Local Testing:**
```bash
# Test with dummy data (simulates Vercel)
USE_DUMMY_DATA=true python website.py

# Test with real data (local mode)
python website.py
```
