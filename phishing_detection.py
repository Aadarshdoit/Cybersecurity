import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
data = pd.read_csv("phishing_urls.csv")
print(data.head())
def extract_features(url):
    features = []
    
    features.append(len(url))                    # Length of URL
    features.append(url.count('.'))              # Number of dots
    features.append(1 if '@' in url else 0)      # @ symbol
    features.append(1 if 'https' in url else 0)  # HTTPS presence
    features.append(sum(c.isdigit() for c in url)) # Count of digits
    features.append(len(re.findall(r'[-_=?%]', url))) # Special chars
    
    return features
X = data['url'].apply(extract_features).tolist()
y = data['label']
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))
def predict_url(url):
    features = extract_features(url)
    result = model.predict([features])
    return "Phishing URL" if result[0] == 1 else "Legitimate URL"
print(predict_url("http://secure-paypal-login.com"))
print(predict_url("https://google.com"))
