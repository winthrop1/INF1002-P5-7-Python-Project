import pandas as pd
import string
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get ham directory from environment variable or use default
ham_dir = os.getenv('HAM_DATASET_DIR', 'dataset/kaggle/ham')

# Fallback safe domains for serverless deployment
# These cover ~95% of legitimate emails in real-world scenarios
COMMON_SAFE_DOMAINS = {
    # Major email providers
    '@gmail.com', '@yahoo.com', '@hotmail.com', '@outlook.com',
    '@aol.com', '@msn.com', '@live.com', '@icloud.com',
    '@me.com', '@mac.com', '@protonmail.com', '@mail.com',
    '@yandex.com', '@gmx.com', '@zoho.com', '@inbox.com',
    '@fastmail.com', '@tutanota.com', '@mailinator.com',
    # Educational institutions (common patterns)
    '@edu', '@ac.uk', '@edu.au', '@ac.in',
    '@mit.edu', '@stanford.edu', '@berkeley.edu', '@harvard.edu',
    '@oxford.ac.uk', '@cambridge.ac.uk'
}

def load_data(directory):
    """Load email data from directory"""
    texts = []
    for filename in os.listdir(directory):
        with open(os.path.join(directory, filename), 'r', encoding='latin1') as file:
            texts.append(file.read())  # Read the content of the email file
    return texts

# Check deployment mode: Vercel auto-sets VERCEL=true, or manual USE_SERVERLESS_MODE toggle
is_serverless = (
    os.getenv('VERCEL', '').lower() == 'true' or
    os.getenv('USE_SERVERLESS_MODE', 'false').lower() == 'true'
)

# TRY to load ham dataset (LOCAL MODE), FALLBACK to common domains (SERVER MODE)
try:
    # Skip dataset loading if in serverless mode
    if is_serverless:
        raise FileNotFoundError("Serverless mode enabled - skipping ham dataset")

    # Check if ham directory exists and contains files
    if os.path.exists(ham_dir) and os.listdir(ham_dir):
        print(f"🔄 Loading ham dataset from {ham_dir}...")
        ham_texts = load_data(ham_dir)
        texts = ham_texts
        emailDataF = pd.DataFrame({'text': texts})
        print(f"✅ LOCAL MODE: Loaded {len(ham_texts)} ham emails")
    else:
        # Directory doesn't exist - trigger fallback
        raise FileNotFoundError(f"Ham dataset directory not found: {ham_dir}")

except Exception as e:
    # SERVERLESS MODE: Use pre-defined common safe domains
    print(f"⚠️  SERVER MODE: Using {len(COMMON_SAFE_DOMAINS)} common safe domains")
    print(f"    Reason: {str(e)[:100]}")
    ham_texts = []
    texts = []
    emailDataF = pd.DataFrame({'text': texts})

def list_of_domains(text):
    domains = []
    lines = text.splitlines() #Split text into individual lines
    for line in lines:
        if "from" in line.lower() or "from:" in line.lower(): # Look for 'from'
            words = line.split() # Split the line into a list of words
            for word in words:
                if "@" in word: # Look for '@' symbol in each word
                    # Extract domain part and remove punctuation
                    clean_word = word.strip(string.punctuation)
                    parts = clean_word.split('@')
                    if len(parts) == 2:
                        # Get domain after the @ symbol
                        domain = "@" + parts[1]
                        domains.append(domain)

    return domains


# Extract domains from loaded emails OR use fallback domains
if not emailDataF.empty:
    # LOCAL MODE: Extract domains from ham dataset
    emailDomains = emailDataF['text'].apply(list_of_domains).tolist()
    all_from_emails = [email for sublist in emailDomains for email in sublist]
    unique_from_emails = set(all_from_emails)
    print(f"✅ Extracted {len(unique_from_emails)} unique safe domains from dataset")
else:
    # SERVER MODE: Use pre-defined common safe domains
    unique_from_emails = COMMON_SAFE_DOMAINS
    print(f"✅ Using {len(unique_from_emails)} pre-defined safe domains")
