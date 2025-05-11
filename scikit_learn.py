import numpy as np
from sklearn.tree import DecisionTreeClassifier

# Load the dataset of binary files
X = np.loadtxt('malware_dataset.csv', delimiter=',')
y = np.loadtxt('malware_labels.csv', delimiter=',')

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a decision tree classifier on the training data
clf = DecisionTreeClassifier()
clf.fit(X_train, y_train)

# Test the classifier on the testing data
y_pred = clf.predict(X_test)

# Print the accuracy of the classifier
print('Accuracy:', clf.score(X_test, y_test))
