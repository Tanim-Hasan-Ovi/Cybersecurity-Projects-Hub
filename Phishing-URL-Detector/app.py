import streamlit as st
import pandas as pd
import joblib
from feature_extractor import extract_features
from urllib.parse import urlparse
import re

# Load the trained model
@st.cache_resource
def load_model():
    return joblib.load('phishing_model.pkl')

model = load_model()

# --- Brand Spoofing Check Function ---
def check_for_brand_spoofing(url):
    cleaned_url = url.replace("https://", "").replace("http://", "").lower()
    hostname = cleaned_url.split('/')[0]
    
    if hostname.startswith("www."):
        hostname = hostname[4:]
        
    # main domain part
    parts = hostname.split('.')
    
    visual_mappings = {'i': 'l', '1': 'l', '0': 'o', '8': 'b', 'q': 'g'}
    target_brands = ['google', 'paypal', 'apple', 'facebook', 'amazon', 'microsoft', 'netflix']

    for part in parts:
        # Step A: Check if the part is exactly a brand (Safe)
        if part in target_brands:
            continue 
            
        # Step B: Check if the part LOOKS like a brand
        standardized_part = "".join(visual_mappings.get(c, c) for c in part)
        for brand in target_brands:
            if standardized_part == brand and part != brand:
                return True, brand
                
    return False, None
# ---------------------------------------------

# Build the User Interface
st.markdown("<h1 style='text-align: center;'>🎣 Phishing URL Detector</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'><b>Stay safe online!</b> Enter a link below to see if it is safe or dangerous.</p>", unsafe_allow_html=True)
st.write("")
st.write("")
# 🌟 FIX: Using st.form so the 'Enter' key works!
with st.form(key='url_form'):
    st.markdown("#### 🔗 Enter URL:")
    user_url = st.text_input("URL", placeholder="e.g., https://www.google.com or paste a suspicious link here...", label_visibility="collapsed")    
    st.write("")
    
    col1, col2, col3 = st.columns([1, 1, 1])
    
    with col2:
        submit_button = st.form_submit_button("🛡️ Analyze URL", use_container_width=True)

if submit_button:
    if user_url:
        with st.spinner("🔍 Scanning URL for security threats..."):
            
            # Extract features from the user's URL
            extracted_features = extract_features(user_url)
            features_df = pd.DataFrame([extracted_features])
            
            # 1. Ask the Machine Learning Model
            prediction = model.predict(features_df)[0]
            scam_warning = ""
            
            # 🌟 NEW: The Whitelist (Trusted Sites Override)
            trusted_domains = ['google.com', 'youtube.com', 'github.com', 'microsoft.com', 'apple.com', 'linkedin.com', 'facebook.com']
            
            # Parse the URL correctly to get the domain
            parse_url = user_url if user_url.startswith('http') else 'https://' + user_url
            domain = urlparse(parse_url).netloc.lower()
            
            # Check if the domain is exactly a trusted domain or a subdomain of it (like gemini.google.com)
            is_trusted = any(domain == t_domain or domain.endswith('.' + t_domain) for t_domain in trusted_domains)
            
            if is_trusted:
                prediction = 0  # Force it to be SAFE! (Overrides ML model)
            else:
                # 2. Heuristic Override 1: Typosquatting (Number in domain)
                if prediction == 0:
                    if extracted_features['digits_in_domain'] > 0 and extracted_features['url_length'] < 30:
                        prediction = 1
                    
                    # --- NEW RULE: Package/Bank Scams ---
                    elif extracted_features['has_suspicious_word'] == 1:
                        if extracted_features['is_https'] == 0 or extracted_features['count_hyphen'] >= 2:
                            prediction = 1
                            scam_warning = "📦 **Scam Detected:** This URL uses tricks common in delivery or account scams!"
                
                # 3. HEURISTIC OVERRIDE 2: Brand Spoofing (I vs L, etc.)
                is_spoofed, target_brand = check_for_brand_spoofing(user_url)
                if is_spoofed:
                     prediction = 1
                     scam_warning = f"🕵️ **Fake Website:** This looks like a fake {target_brand.capitalize()} website!"
            
        # 🌟 UI Upgrade: Better Results Display
        st.markdown("---")
        st.subheader("📊 Analysis Result")
        
        if prediction == 1:
            st.error("🚨 **WARNING: This URL looks like a Phishing attempt!**")
            if scam_warning:
                 st.warning(scam_warning)
        else:
            st.success("✅ **SAFE: This URL appears to be legitimate.**")
            if is_trusted:
                st.info("🛡️ **Verified Trusted Domain:** This is a known secure website.")
            st.balloons() # 🎈 Fun animation for safe URLs
            
        # 🌟 UI Upgrade: Display key features as professional Metric Cards
        st.markdown("### 🔍 Quick URL Scan Details")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(label="Secure (HTTPS)", value="Yes" if extracted_features['is_https'] == 1 else "No")
        with col2:
            st.metric(label="Suspicious Words", value="Found" if extracted_features['has_suspicious_word'] == 1 else "Clean")
        with col3:
            st.metric(label="URL Length", value=extracted_features['url_length'])
            
        # Optional: Show the raw extracted features in an expander
        with st.expander("⚙️ View Raw Extracted Features (Developer Mode)"):
            st.json(extracted_features)
            
    else:
        st.warning("⚠️ Please enter a URL first.")