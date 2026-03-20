import streamlit as st
import pandas as pd
import joblib
from feature_extractor import extract_features
import re

# Load the trained model
@st.cache_resource
def load_model():
    return joblib.load('phishing_model.pkl')

model = load_model()

# --- NOTUN: Brand Spoofing Check Function ---
def check_for_brand_spoofing(url):
    # Clean the URL to get just the hostname (remove http, https, www)
    cleaned_url = url.replace("https://", "").replace("http://", "").lower()
    hostname = cleaned_url.split('/')[0]
    
    if hostname.startswith("www."):
        hostname = hostname[4:]
        
    # Visual mappings for common tricks
    visual_mappings = {'i': 'l', '1': 'l', '0': 'o', '8': 'b', 'q': 'g'}
    
    # Apply mapping to the hostname
    standardized_hostname = "".join(visual_mappings.get(c, c) for c in hostname)
    
    target_brands = ['google', 'paypal', 'apple', 'facebook', 'amazon', 'microsoft', 'netflix']
    
    for brand in target_brands:
        # THE SMART FIX:
        # Check if the fake name has the brand inside it (e.g., 'google' is inside 'gemlnl.google.com')
        # AND make sure the original URL DOES NOT have the correct spelling (to protect the real gemini.google.com)
        if brand in standardized_hostname and brand not in hostname:
            return True, brand
            
    return False, None
# ---------------------------------------------

# Build the User Interface
st.title("🎣 Phishing URL Detector")
st.write("Enter a URL below to check if it's safe or potentially malicious.")

# Input box for the user
user_url = st.text_input("Enter URL (e.g., https://www.google.com):")


if st.button("Analyze URL"):
    if user_url:
        # Extract features from the user's URL
        extracted_features = extract_features(user_url)
        features_df = pd.DataFrame([extracted_features])
        
        # 1. Ask the Machine Learning Model
        prediction = model.predict(features_df)[0]
        scam_warning = ""
        
        # 2. Heuristic Override 1: Typosquatting (Number in domain)
        if prediction == 0:
            if extracted_features['digits_in_domain'] > 0 and extracted_features['url_length'] < 30:
                prediction = 1
            
            # --- NEW RULE: Package/Bank Scams ---
            # If it has a suspicious word AND (is not secure OR has 2+ hyphens)
            elif extracted_features['has_suspicious_word'] == 1:
                if extracted_features['is_https'] == 0 or extracted_features['count_hyphen'] >= 2:
                    prediction = 1
                    scam_warning = "📦 **Scam Detected:** This URL uses tricks common in delivery or account scams!"
        
        # 3. HEURISTIC OVERRIDE 2: Brand Spoofing (I vs L, etc.)
        is_spoofed, target_brand = check_for_brand_spoofing(user_url)
        if is_spoofed:
             prediction = 1
             scam_warning = f"🕵️ **Fake Website:** This looks like a fake {target_brand.capitalize()} website!"
        
        # Display results
        st.markdown("---")
        if prediction == 1:
            st.error("🚨 **WARNING: This URL looks like a Phishing attempt!**")
            if scam_warning:
                 st.warning(scam_warning)
        else:
            st.success("✅ **SAFE: This URL appears to be legitimate.**")
            
        # Optional: Show the extracted features for transparency
        with st.expander("See extracted features"):
            st.json(extracted_features)
    else:
        st.warning("Please enter a URL first.")