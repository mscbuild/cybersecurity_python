from Crypto.Cipher import AES

# Generate a random encryption key
key = b'SuperSecretKey123'

# Create an AES cipher object
cipher = AES.new(key, AES.MODE_EAX)

# Encrypt some data
data = b'This is some sensitive data'
ciphertext, tag = cipher.encrypt_and_digest(data)

# Decrypt the data
cipher = AES.new(key, AES.MODE_EAX, cipher.nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)

# Print the result
print(plaintext.decode('utf-8'))
