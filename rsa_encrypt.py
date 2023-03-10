import rsa

(pub_key, priv_key) = rsa.newkeys(512)

def encrypt_message(message, pub_key):
    crypto = rsa.encrypt(message, pub_key)
    return crypto

def decrypt_message(crypto, priv_key):
    decrypt = rsa.decrypt(crypto, priv_key)
    return decrypt.decode('utf-8')

crypto = encrypt_message(input('Type your message: ').encode('utf-8'), pub_key)
decrypt = decrypt_message(crypto, priv_key)

print(f'Encrypted message: {crypto}\n')
print(f'Decrypted message: {decrypt}')



