from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(16)

def encrypt(message):

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipher_text, tag = cipher.encrypt_and_digest(message.encode('ascii'))
    
    return nonce, cipher_text, tag

def decrypt(nonce, cipher_text, tag):

    cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
    plain_text = cipher.decrypt(cipher_text)

    try:
        cipher.verify(tag)
        return plain_text.decode('ascii')
    
    except ValueError:
        return False

nonce, cipher_text, tag = encrypt(input('Type your message: '))
plain_text = decrypt(nonce, cipher_text, tag)

print(f'Encrypted message: {cipher_text}')

if not plain_text:
    print('Key incorrect or message corrupted')
else:
    print(f'decrypted message: {plain_text}')
