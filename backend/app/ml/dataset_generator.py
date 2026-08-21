import random
import pandas as pd
from .feature_extractor import extract_features
from ..core.config import settings

LEGITIMATE_BASE_DOMAINS = [
    # Top tech & search
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "yahoo.com", "reddit.com", "netflix.com", "linkedin.com", "instagram.com",
    "microsoft.com", "apple.com", "github.com", "twitter.com", "cloudflare.com",
    "spotify.com", "stackoverflow.com", "medium.com", "nytimes.com", "cnn.com",
    "bbc.co.uk", "walmart.com", "ebay.com", "dropbox.com", "salesforce.com",
    "adobe.com", "zoom.us", "quora.com", "office.com", "paypal.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "openai.com", "anthropic.com",
    "huggingface.co", "gitlab.com", "atlassian.net", "figma.com", "canva.com",
    "notion.so", "slack.com", "discord.com", "telegram.org", "twitch.tv",
    "imdb.com", "booking.com", "airbnb.com", "etsy.com", "shopify.com",
    "uber.com", "lyft.com", "doordash.com", "coursera.org", "edx.org", "udemy.com",
    "python.org", "rust-lang.org", "golang.org", "nodejs.org", "docker.com",
    "pypi.org", "npmjs.com", "supabase.com", "vercel.app", "netlify.app",

    # Education, Government & Healthcare
    "mit.edu", "harvard.edu", "stanford.edu", "berkeley.edu", "ox.ac.uk", "cam.ac.uk",
    "nih.gov", "cdc.gov", "who.int", "nasa.gov", "weather.com", "europa.eu",
    "incometax.gov.in", "gov.uk", "australia.gov.au", "nationalgeographic.com",

    # Legitimate Hyphenated Brands and Organization Domains
    "mercedes-benz.com", "wal-mart.com", "t-mobile.com", "roll-royce.com",
    "city-library-catalog.org", "family-counseling-services.org", "austin-law-firm.com",
    "quantum-computing-research-lab.org", "green-valley-organic-farm.com",
    "modern-architecture-studio.com", "craft-beer-brewery-austin.com",
    "digital-art-gallery-showcase.com", "acme-consulting-group.com",
    "johns-bakery-shop.com", "my-local-dental-clinic.org", "travelwithsarah.net",
    "indie-game-developers.net", "premium-auto-repair-chicago.com",
    "state-university-portal.edu", "global-logistics-solutions.com",
    "creative-media-agency.co.uk", "cloud-native-devops.io", "tech-blog-weekly.dev"
]

LEGITIMATE_PATHS = [
    "", "/", "/about", "/about-us", "/contact-us", "/products", "/services", "/terms-of-service",
    "/privacy-policy", "/search?q=machine+learning+cybersecurity+2026", 
    "/news/2026/08/technology-update-global-announcement",
    "/user/profile/settings?tab=security&mfa=enabled", 
    "/docs/api/v1/getting-started-with-python-sdk", 
    "/blog/how-to-secure-your-account-with-hardware-keys",
    "/explore/trending/technology-and-software", 
    "/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array",
    "/Apple-iPhone-15-Pro-128GB/dp/B0CHWRFH3P/?tag=affiliate-20&ref=sr_1_1",
    "/support/knowledge-base/article-1029?hl=en&lang=en-US", 
    "/downloads/latest-version/release-notes-2026-v4.2.1", 
    "/pricing/enterprise/calculator?tier=business&users=50",
    "/careers/open-positions/senior-security-engineer-lead", 
    "/events/2026/annual-cybersecurity-summit-registration", 
    "/community/discussions/topic/9421-explainable-ai-models",
    "/watch?v=dQw4w9WgXcQ&feature=emb_title",
    "/in/john-doe-cybersecurity-analyst-981249",
    "/en-us/security/business/threat-intelligence-reports",
    "/products/workspace/gmail/add-ons-management",
    "/torvalds/linux/blob/master/README.md",
    "/item?id=38910245&comments=true",

    # Authentic Authentication & Verification Web Paths
    "/login", "/signin", "/user/login.php", "/accounts/login",
    "/client-area/signin", "/patient-portal/login", "/auth/login.html",
    "/account/login?redirect=%2Fdashboard",
    "/portal/verify-email?token=84920193849102",
    "/auth/reset-password?token=ab87c9f801cd4e",
    "/checkout?step=payment&session=98120348",
    "/support/ticket/982103?auth=true",
    "/catalog/books?category=science&sort=newest&page=2",
    "/docs/guides/auth/overview",
    "/dashboard/projects/98120/settings"
]

LEGITIMATE_SUBDOMAINS = [
    "", "www.", "app.", "api.", "m.", "help.", "support.", "docs.", "mail.", 
    "blog.", "news.", "portal.", "dev.", "cloud.", "workspace.", "accounts.",
    "secure.", "auth.", "id.", "dash.", "myaccount.", "client."
]

PHISHING_BRANDS = [
    "paypal", "apple", "microsoft", "chase-bank", "netflix", "wellsfargo",
    "bankofamerica", "google-security", "facebook-verify", "amazon-support",
    "binance-wallet", "coinbase-login", "metamask-auth", "instagram-badge",
    "dhl-tracking", "fedex-delivery", "irs-tax-refund", "usps-package-redirection"
]

PHISHING_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz",
    ".fit", ".icu", ".monster", ".cam", ".work", ".click", ".link"
]

PHISHING_SUBDOMAINS = [
    "security-update", "account-verification", "login-portal", "auth-service",
    "secure-banking", "validation-center", "confirm-identity", "billing-alert",
    "suspended-account-notice", "ssl-encryption-check", "pass-reset", "webscr-cmd",
    "recover-account", "wallet-validation", "identity-confirm"
]

PHISHING_PATHS = [
    "/signin.php?token=928340192830192&session=active",
    "/login.html?redirect=https%3A%2F%2Faccount.protection.com&id=882",
    "/verify/account-recovery.php?user_id=782194&auth=required",
    "/webscr?cmd=_login-run&dispatch=5885d80a13c0db1f8e263663d3faee8d",
    "/secure/billing-update.asp?id=secure998124&step=card_info",
    "/auth/validation?challenge=2fa-bypass&client=mobile",
    "/cgi-bin/s-login.cgi?action=verify_credentials&dest=secure",
    "/update-password/form.php?email=victim@target.com",
    "/identity/unlock-account?ref=urgent_security_flag&code=9128",
    "/portal/user/authentication/login-session.php?k=ab87f9e801cd4"
]

def generate_benchmark_dataset(sample_size: int = 5000) -> pd.DataFrame:
    """
    Generates a realistic, diverse dataset of legitimate and phishing URLs
    with extracted features and ground truth labels (0 = Legitimate, 1 = Phishing).
    """
    rows = []
    half_size = sample_size // 2
    
    # 1. Generate Legitimate URLs (50%)
    for _ in range(half_size):
        domain = random.choice(LEGITIMATE_BASE_DOMAINS)
        path = random.choice(LEGITIMATE_PATHS)
        scheme = "https://" if random.random() > 0.03 else "http://"
        sub = random.choice(LEGITIMATE_SUBDOMAINS)
            
        url = f"{scheme}{sub}{domain}{path}"
        feats, _, _, _ = extract_features(url)
        feats["url"] = url
        feats["label"] = 0  # Legitimate
        rows.append(feats)
        
    # 2. Generate Phishing URLs (50%)
    for _ in range(half_size):
        attack_type = random.choice([
            "typosquat", "subdomain_stack", "ip_host", "shortener_phish", 
            "keyword_stuff", "at_symbol", "token_harvest", "suspicious_tld",
            "double_slash", "brand_spoof"
        ])
        brand = random.choice(PHISHING_BRANDS)
        tld = random.choice(PHISHING_TLDS)
        path = random.choice(PHISHING_PATHS)
        scheme = random.choice(["http://", "http://", "https://"])
        
        if attack_type == "ip_host":
            ip = f"{random.randint(11,210)}.{random.randint(1,250)}.{random.randint(1,250)}.{random.randint(1,250)}"
            url = f"{scheme}{ip}{path}"
        elif attack_type == "subdomain_stack":
            sub1 = random.choice(PHISHING_SUBDOMAINS)
            sub2 = random.choice(PHISHING_SUBDOMAINS)
            url = f"{scheme}{sub1}.{brand}.{sub2}{tld}{path}"
        elif attack_type == "at_symbol":
            decoy = random.choice(["google.com", "paypal.com", "apple.com", "microsoft.com"])
            url = f"{scheme}{decoy}@{brand}-security{tld}{path}"
        elif attack_type == "double_slash":
            url = f"{scheme}www.{brand}-security{tld}//redirect?target=login&auth=true"
        elif attack_type == "shortener_phish":
            short = random.choice(["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"])
            code = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=7))
            url = f"http://{short}/{code}?malicious_redirect=login_phish"
        elif attack_type == "keyword_stuff":
            url = f"{scheme}login-verify-{brand}-account-security-update-portal{tld}{path}"
        elif attack_type == "token_harvest":
            token = "".join(random.choices("0123456789abcdef", k=32))
            url = f"{scheme}{brand}-portal-auth{tld}/verify?session_token={token}&redirect=login"
        elif attack_type == "suspicious_tld":
            url = f"{scheme}{brand}-secure-login{tld}/index.php?user=verify"
        elif attack_type == "brand_spoof":
            url = f"{scheme}secure-banking-{brand}-update{tld}/customer-service/verification"
        else: # typosquat
            typo_brand = brand.replace("a", "4").replace("o", "0").replace("l", "1").replace("e", "3")
            url = f"{scheme}www.{typo_brand}-support{tld}{path}"
            
        feats, _, _, _ = extract_features(url)
        feats["url"] = url
        feats["label"] = 1  # Phishing
        rows.append(feats)
        
    df = pd.DataFrame(rows)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    # Save benchmark dataset
    df.to_csv(settings.BENCHMARK_DATASET_PATH, index=False)
    print(f"[+] Generated benchmark dataset with {len(df)} samples at {settings.BENCHMARK_DATASET_PATH}")
    return df

def get_or_create_dataset() -> pd.DataFrame:
    return generate_benchmark_dataset(5000)
