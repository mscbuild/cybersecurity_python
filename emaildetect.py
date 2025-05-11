import nltk
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
from email.parser import Parser
import re

# Load pre-labeled dataset (phishing vs. legitimate emails)
def load_dataset():
    # Placeholder: Replace with your dataset (CSV with 'label' and 'email_content')
    dataset = pd.read_csv("phishing_emails.csv")
    return dataset

# Preprocess email content
def preprocess_email(content):
    # Lowercase, remove special characters, URLs, and emails
    content = content.lower()
    content = re.sub(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", "", content)  # Remove URLs
    content = re.sub(r"[^\w\s]", "", content)  # Remove non-alphabetical characters
    return content

# Train phishing detection model
def train_model():
    # Load dataset
    data = load_dataset()

    # Preprocess emails
    data['email_content'] = data['email_content'].apply(preprocess_email)

    # Vectorize email content (convert text to numerical features)
    vectorizer = CountVectorizer(stop_words='english')
    X = vectorizer.fit_transform(data['email_content'])
    y = data['label']  # 'label' is 1 for phishing, 0 for legitimate

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train Naive Bayes model
    model = MultinomialNB()
    model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Phishing email detection accuracy: {accuracy * 100:.2f}%")

    return model, vectorizer

# Detect phishing email using the trained model
def detect_phishing_email(model, vectorizer, email_content):
    preprocessed_content = preprocess_email(email_content)
    features = vectorizer.transform([preprocessed_content])
    prediction = model.predict(features)
    return "Phishing" if prediction[0] == 1 else "Legitimate"

# Example usage
if __name__ == "__main__":
    model, vectorizer = train_model()

    email_to_check = """Subject: Urgent account verification
    Dear user, we have detected suspicious activity on your account. Please click the link to verify your identity.
    http://maliciouslink.com/verify"""

    result = detect_phishing_email(model, vectorizer, email_to_check)
    print(f"The email is: {result}")
