import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
from feature_extractor import extract_features

# 1. Load the REAL dataset
print("Loading real dataset...")
df = pd.read_csv('phishing_site_urls.csv') 

# The real dataset has 549,000+ rows! 
# Let's take a random mix of 20,000 rows so it trains quickly on your Mac/PC.
# (If you want higher accuracy later, you can increase this number!)
print("Sampling 100,000 URLs for faster training...")
df = df.sample(n=100000, random_state=42)

# 2. Fix the Labels
# The Kaggle dataset uses "bad" for phishing and "good" for safe. 
# We need to change these to 1 (phishing) and 0 (safe) for the ML model.
df['Label'] = df['Label'].map({'bad': 1, 'good': 0})

# 3. Extract features for the 20,000 URLs
print("Extracting features from URLs (this might take a minute or two)...")
features_list = df['URL'].apply(extract_features).tolist()

X = pd.DataFrame(features_list) # The extracted number features
y = df['Label']                 # The 0s and 1s

# 4. Split data into training (80%) and testing (20%)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Train the Random Forest Model
print("Training the Machine Learning model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 6. Test the Model's Accuracy
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"✅ Model trained successfully with real data! Accuracy: {accuracy * 100:.2f}%")

# 7. Save the model
joblib.dump(model, 'phishing_model.pkl')
print("Model saved as 'phishing_model.pkl'. You can now run the web app!")