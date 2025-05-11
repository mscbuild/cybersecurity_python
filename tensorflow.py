import tensorflow as tf
from tensorflow import keras

# Load the dataset of malware samples
data = keras.datasets.mnist
(x_train, y_train), (x_test, y_test) = data.load_data()

# Normalize the pixel values
x_train = x_train / 255.0
x_test = x_test / 255.0

# Define the model architecture
model = keras.Sequential([
    keras.layers.Flatten(input_shape=(28, 28)),
    keras.layers.Dense(128, activation='relu'),
    keras.layers.Dense(10, activation='softmax')
])

# Compile the model
model.compile(optimizer='adam',
              loss='sparse_categorical_crossentropy',
              metrics=['accuracy'])

# Train the model on the training data
model.fit(x_train, y_train, epochs=5)

# Evaluate the model on the testing data
test_loss, test_acc = model.evaluate(x_test, y_test)

# Print the test accuracy
print('Test accuracy:', test_acc)
