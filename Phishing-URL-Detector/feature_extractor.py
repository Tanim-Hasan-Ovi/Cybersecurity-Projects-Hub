from urllib.parse import urlparse

def extract_features(url):
    features = {}
    
    url = str(url)
    parsed_url = urlparse(url)
    
    # 1. Length Features
    features['url_length'] = len(url)
    features['hostname_length'] = len(parsed_url.netloc) if parsed_url.netloc else 0
    
    # 2. Character Counts
    features['count_at'] = url.count('@')
    features['count_hyphen'] = url.count('-')
    features['count_question'] = url.count('?')
    features['count_equals'] = url.count('=')
    features['count_dots'] = url.count('.')
    
    # NOTUN FEATURE: Domain er bhitor songkha (numbers) ache kina
    domain = parsed_url.netloc if parsed_url.netloc else ""
    features['digits_in_domain'] = sum(c.isdigit() for c in domain)
    
    # 3. Lexical Features (Checking for suspicious words)
    suspicious_words = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'free', 'package', 'delivery', 'tracking', 'usps', 'fedex', 'dhl', 'post', 'urgent', 'suspended', 'locked', 'invoice']
    features['has_suspicious_word'] = 1 if any(word in url.lower() for word in suspicious_words) else 0
    
    # 4. Security Check
    features['is_https'] = 1 if parsed_url.scheme == 'https' else 0
    
    return features