from flask import Flask, request, render_template, redirect, url_for, session, jsonify  #import flask and needed modules
from email_manage import parse_email_file #import function to parse email structure
from domainchecker import domaincheck #import function to verify domain authenticity
from suspiciouswords import classify_email #import function to detect suspicious keywords
from suspiciousurl import assessing_risk_scores #get_urls_from_email_file
from userdatastore import storeDatainTxt #import function to store analysis results
from logger import setup_logging, log_analysis, log_admin_login_success, log_admin_login_failure, log_admin_logout, log_email_sent, log_email_failed, log_data_storage_success  #logging functions
import os #work with folders in file systems
import smtplib #send emails via SMTP protocol
import socket #handle network-related errors
from email.message import EmailMessage #construct email messages
from email.utils import parseaddr #parse email addresses
from dotenv import load_dotenv #for loading environment variables
import glob #find files matching patterns
from collections import Counter #count keyword frequencies
import re #regular expressions for pattern matching
import time  #for runtime measurement

#load environment variables from .env file
load_dotenv()

#configure logging
setup_logging()

#initialize flask app
app = Flask(__name__,
            template_folder=os.getenv('TEMPLATE_FOLDER', 'website'),
            static_folder='website',  #tells Flask where static files are
            static_url_path='')       #makes URLs like /css/styles.css work

#set secret key for session management (encrypts session cookies)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')  #add to your .env file

#admin credentials loaded from environment variables for security
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', '1')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '1')

def organize_keywords_by_category(keywords_list):
    #organize keywords into categories based on tuples (location, keyword)
    #initialize dictionary with empty lists for each category
    organized = {
        'subject': [],
        'early_body': [],
        'remaining_body': []
    }

    #iterate through keyword tuples and categorize by location
    for location, keyword in keywords_list:
        if location == 'subject':
            organized['subject'].append(f"Found: '{keyword}'")
        elif location == 'early_body':
            organized['early_body'].append(f"Found: '{keyword}'")
        elif location == 'remaining_body':
            organized['remaining_body'].append(f"Found: '{keyword}'")
    
    return organized

@app.route('/', methods=['GET', 'POST']) #accepts both get and post
def upload_file():
    #variables to hold results
    reasons = [] 
    url_reason_pairs = []
    classification = None
    EmailDomainMsg = ''
    DistanceCheckMsg = ''
    emailnotify = ''
    storing_notify = ''
    success = bool
    keywords = [] #list of detected keywords
    #organized keywords by location (subject, early_body, remaining_body)
    organized_keywords = {
    'subject': [],
    'early_body': [],
    'remaining_body': []
}
    total_score = 0
    email_text = ''
    email_title = ''
    email_subject = ''
    email_body = ''
    risk_level = ''
    total_risk_scoring = 0
    number_of_urls = 0
    number_of_unique_domains = 0

    if request.method == 'POST': #handle submissions
        #retrieve uploaded file and user email from form
        file = request.files.get('emailfile')
        useremail = request.form.get('userEmail')

        #validate file upload
        if not file:
            classification = ("Please upload a valid email file.")
        else:
            # Get filename for logging
            filename = file.filename if file.filename else "unknown"

            # Start runtime measurement
            start_time = time.time()

            # Read and decode the uploaded file
            email_text = file.read().decode('utf-8', errors='ignore') #use utf-8 to read and decode, ignore decoding errors

            # Parse email using the parse_email_file function
            email_title, email_subject, email_body = parse_email_file(email_text)

            # Domain check
            EmailDomainMsg, DistanceCheckMsg, domain_suspicion_score = domaincheck(email_title)

            # URL analysis
            reasons, url_suspicion_score, url_reason_pairs, number_of_urls, number_of_unique_domains = assessing_risk_scores(email_body)

            # Classify the email using the original detection system
            keywords, keywords_suspicion_score = classify_email(email_subject, email_body)
            
            # Organize keywords by category for better display
            organized_keywords = organize_keywords_by_category(keywords)

            # Apply component-level caps (prevents any single component from dominating)
            domain_capped = min(domain_suspicion_score, int(os.getenv("MAX_DOMAIN_SCORE", "5")))       # Cap domain at 5
            url_capped = min(url_suspicion_score, int(os.getenv("MAX_URL_SCORE", "6")))            # Cap URLs at 6
            keywords_capped = min(keywords_suspicion_score, int(os.getenv("MAX_KEYWORD_SCORE", "15")))  # Cap keywords at 15

            total_risk_scoring = domain_capped + url_capped + keywords_capped
                
            if total_risk_scoring >= int(os.getenv("VERY_HIGH_RISK_THRESHOLD", "16")):
                risk_level = "VERY HIGH"
            elif total_risk_scoring >= int(os.getenv("HIGH_RISK_THRESHOLD", "12")):
                risk_level = "HIGH"
            elif total_risk_scoring >= int(os.getenv("MEDIUM_RISK_THRESHOLD", "8")):
                risk_level = "MEDIUM"
            elif total_risk_scoring >= int(os.getenv("LOW_RISK_THRESHOLD", "4")):
                risk_level = "LOW"
            else:
                risk_level = "VERY LOW"

            # risk_level, suspicion_score, reasons = assessing_risk_scores(email_body)
            
            if "safe" in EmailDomainMsg.lower() and total_risk_scoring >int(os.getenv("MEDIUM_RISK_THRESHOLD", "8")):
                EmailDomainMsg += "However, potential phishing is detected!"

            classification = "Safe" if total_risk_scoring <= int(os.getenv("PHISHING_SCORE", "8")) else "Phishing"

            # End runtime measurement and print to console
            runtime = time.time() - start_time
            print(f"\n=== Analysis Runtime: {runtime:.4f} seconds ===\n")

            # Log analysis results using the logger module
            log_analysis(
                filename=filename,
                runtime=runtime,
                classification=classification,
                risk_level=risk_level,
                total_risk_scoring=total_risk_scoring,
                domain_capped=domain_capped,
                url_capped=url_capped,
                keywords_capped=keywords_capped,
                keywords_count=len(keywords),
                number_of_urls=number_of_urls,
                number_of_unique_domains=number_of_unique_domains,
                url_reason_pairs=url_reason_pairs,
                EmailDomainMsg=EmailDomainMsg
            )

            # Store analysis results in a text file (skip in serverless mode)
            is_serverless = os.getenv('VERCEL', '').lower() == 'true'
            if is_serverless:
                storing_notify = "Data storage disabled in serverless mode."
                success = False
            else:
                storing_notify, success = storeDatainTxt(classification, keywords,total_risk_scoring, EmailDomainMsg, email_text, url_reason_pairs, number_of_urls)
                if success:
                    log_data_storage_success()

            # Send email report to user
            if useremail:
                admin_email = os.getenv('EMAIL_ADDRESS')
                admin_key = os.getenv('EMAIL_KEY')
                
                def format_url_analysis_for_email(url_reason_pairs):
                    url_email_text = []
                    for pair in url_reason_pairs:
                        # Header for URL
                        url_email_text.append(f"URL: {pair['url']}")
                        # Reasons list
                        if pair.get('reasons'):
                            for reason in pair['reasons']:
                                url_email_text.append(f"- {reason}")
                        else:
                            url_email_text.append("- No specific issues found for this URL")
                        url_email_text.append("")  # Add empty line for spacing
                    return "\n".join(url_email_text)
                
                formatted_pairs = format_url_analysis_for_email(url_reason_pairs)
                
                report_body = (
                "----- Email Analysis Result -----\n\n"
                    f"Classification: {classification}\n\n"
                    f"Total Risk Score: {total_risk_scoring}\n"
                    f"Overall Risk Level: {risk_level}\n\n"
                    "----- Analysis Details -----\n\n"
                    f"URL Analysis: {formatted_pairs}\n\n"
                    f"Keywords Found: {', '.join(keyword for _, keyword in keywords) if keywords else 'None'}\n\n"
                    f"Domain Check: {EmailDomainMsg}\n"
                    f"Distance Check: {DistanceCheckMsg}\n\n"
            
                    "Thank you for using our email phishing analysis service."
                )

                msg = EmailMessage()
                msg['From'] = admin_email
                msg['To'] = useremail
                msg['Subject'] = 'Your Email Phishing Analysis Report'
                msg.set_content(report_body)

                try:
                    server = smtplib.SMTP('smtp.gmail.com', 587)
                    server.starttls()
                    server.login(admin_email, admin_key) #app password
                    server.send_message(msg)
                    server.quit()
                    emailnotify = "Email sent successfully."
                    log_email_sent()

                except (socket.gaierror, smtplib.SMTPException, Exception) as e:
                        emailnotify = f"Failed to send email: {e}"
                        log_email_failed(type(e).__name__)

            
    return render_template("index.html",
                        classification=classification, #classification
                        keywords=keywords, #keywords found
                        organized_keywords=organized_keywords, #organise keywords 
                        total_score=total_score, #risk score
                        email_content=email_text, #original email content
                        email_title=email_title, #parsed email title
                        email_subject=email_subject, #parsed email subject
                        email_body=email_body, #parsed email body
                        EmailDomainMsg=EmailDomainMsg,#domain check message
                        DistanceCheckMsg=DistanceCheckMsg, #distance check message
                        reasons=reasons, #url analysis reasons
                        risk_level=risk_level,#risk scoring of the whole email
                        total_risk_scoring=total_risk_scoring,
                        emailnotify=emailnotify, #email sending notification
                        storing_notify = storing_notify,#data storage notification
                        url_reason_pairs = url_reason_pairs,#list of what url is being assessed and its reasons
                        number_of_urls = number_of_urls, #number of urls found in the email
                        number_of_unique_domains = number_of_unique_domains, #number of unique domains found in the email
                        success = success)

def get_dummy_dashboard_data():
    """Generate dummy data for dashboard when in serverless mode or no stored data available"""
    dummy_data = {
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
    return dummy_data

def parse_stored_emails():
    """Parse all email data files and extract statistics"""
    # Check if we're in serverless mode (Vercel) or local mode
    is_serverless = os.getenv('VERCEL', '').lower() == 'true' or os.getenv('USE_DUMMY_DATA', '').lower() == 'true'

    if is_serverless:
        print("Running in serverless mode - using dummy data for dashboard")
        return get_dummy_dashboard_data()

    safe_count = 0
    phishing_count = 0
    all_keywords = []

    # Extract all .txt files from safe_keep folder
    folder_path = os.path.join(os.path.dirname(__file__), 'dataset', 'safe_keep', '*.txt')
    files = glob.glob(folder_path)

    print(f"Print: Found {len(files)} files to parse")

    # If no files found, return dummy data
    if not files:
        print("No stored files found - using dummy data")
        return get_dummy_dashboard_data()

    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Extract classification
                classification_match = re.search(r'Classification:\s*(Safe|Phishing)', content, re.IGNORECASE)
                if classification_match:
                    classification = classification_match.group(1)
                    if classification.lower() == 'safe':
                        safe_count += 1
                    else:
                        phishing_count += 1

                # Extract keywords from tuple format: ('location', 'keyword')
                # This matches the exact format from your stored files
                keyword_pattern = r"\('(?:subject|early_body|remaining_body)',\s*'([^']+)'\)"
                matches = re.findall(keyword_pattern, content)

                if matches:
                    print(f"Print: Found {len(matches)} keywords in {os.path.basename(file_path)}")
                    all_keywords.extend(matches)

        except Exception as e:
            print(f"ERROR parsing {file_path}: {e}")
            continue

    print(f"Print: Total keywords found: {len(all_keywords)}")

    # Clean keywords and count frequencies
    if all_keywords:
        # Remove duplicates per analysis (convert to lowercase for consistent counting)
        cleaned_keywords = [kw.strip().lower() for kw in all_keywords if kw and kw.strip()]
        keyword_counter = Counter(cleaned_keywords)
        top_keywords = keyword_counter.most_common(5)
        print(f"Print: Top 5 keywords: {top_keywords}")
    else:
        top_keywords = []
        print("Print: No keywords found in any files!")

    return {
        'safe_count': safe_count,
        'phishing_count': phishing_count,
        'top_keywords': top_keywords,
        'total_emails': safe_count + phishing_count
    }

@app.route('/admin-login-json', methods=['POST'])
def admin_login_json():
    #aPI endpoint for admin authentication
    #receives JSON credentials and returns success/failure response
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    #verify credentials against environment variables
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True #set session flag
        log_admin_login_success() #log successful login
        return jsonify({"success": True})
    
    #log failed login attempt
    log_admin_login_failure()
    return jsonify({"success": False, "error": "Invalid email or password."})


@app.route('/admin')
def admin_page():
    #admin dashboard page
    #requires authentication via session
    if not session.get('admin_logged_in'):
        return redirect(url_for('upload_file')) #redirect to homepage if not authenticated
    return render_template("adminPage.html") #render admin dashboard


@app.route('/logout')
def logout():
    #admin logout endpoint
    #clears session and redirects to homepage
    log_admin_logout() #log logout event
    session.pop('admin_logged_in', None) #remove session flag
    return redirect(url_for('upload_file')) #redirect to homepage

@app.route('/api/dashboard-data')
def dashboard_data():
    #aPI endpoint to provide dashboard statistics
    #returns JSON data for charts and counters on admin dashboard
    
    # #verify admin authentication
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    
    data = parse_stored_emails() #parse all stored emails to generate statistics
    
    #ensure we always return at least empty data for the bar chart
    top_keywords_data = [
        {"keyword": keyword, "count": count} 
        for keyword, count in data['top_keywords']
    ]
    
    #if no keywords found, return empty list (not None)
    if not top_keywords_data:
        top_keywords_data = []
    
    #construct response dictionary with all dashboard data
    response_data = {
        "safe_count": data['safe_count'],
        "phishing_count": data['phishing_count'],
        "top_keywords": top_keywords_data,
        "total_emails": data['total_emails']
    }

    print(f"API Response: {response_data}") #debug output
    
    return jsonify(response_data) #return JSON response

if __name__ == "__main__": #run website
    app.run(debug=True) #enable debug mode for development (auto-reload on code changes)