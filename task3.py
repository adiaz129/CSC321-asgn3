from Crypto.Util import number
import random
import binascii
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def make_keys():
    p = number.getPrime(2048)
    q = number.getPrime(2048)
    n = p * q
    totient = (p - 1) * (q - 1)
    e = 65537
    d = mult_inverse(e, totient)
    return ((e, n), (d, n))
    
    
def mult_inverse(e, totient):
    t0 = totient
    y = 0
    x = 1
 
    while (e > 1):
        # q is quotient
        q = e // totient
        t = totient
        totient = e % totient
        e = t
        t = y
        # Update x and y
        y = x - q * y
        x = t
    # Make x positive
    if (x < 0):
        x = x + t0
    return x

def encrypt(public_key, plain_text):
    e = public_key[0]
    n = public_key[1]
  
    if plain_text >= n:
        raise ValueError("plain text too large")
    
    cipher_text = pow(plain_text, e, n)
    return cipher_text

def decrypt(private_key, cipher_text):
    d = private_key[0]
    n = private_key[1]

    plain_text = pow(cipher_text, d, n)
    return plain_text

def string_to_int(message):
    int_message = int(binascii.hexlify(message.encode('utf-8')).decode('utf-8'), 16)
    return int_message

def int_to_string(int_message):
    hex_message = hex(int_message)[2:]
    message = binascii.unhexlify(hex_message).decode()
    return message

def SHA_AES_encrypt(message, s, iv):
    cipher = AES.new(s, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(bytes(message, 'utf-8'), AES.block_size))
    return ciphertext

def SHA_AES_decrypt(cipher_message, k, iv):
    decrypted = AES.new(k, AES.MODE_CBC, iv)
    plaintext = unpad(decrypted.decrypt(cipher_message), AES.block_size)
    return plaintext

def RSA_simulation():
    public_key, private_key = make_keys()
    iv = get_random_bytes(16)
    key = "This is the key"
    message = "This is the message"
    print(message)
    print(key)
    key = string_to_int(key)
    enc = encrypt(public_key, key)
    print("encrypted key: ", enc)
    dec = decrypt(private_key, enc)
    key = int_to_string(dec)
    print("decrypted key: ", key)
    key = SHA256.new(str(key).encode('utf-8')).digest()
    cipher = SHA_AES_encrypt(message, key, iv)
    print("encrypted message: ", cipher)
    key = SHA_AES_decrypt(cipher, key, iv).decode('utf-8', "ignore")
    print("decrypted message: ", key)

def RSA_MITM_simulation():
    public_key, private_key = make_keys()
    iv = get_random_bytes(16)
    key = "This is the original key"
    message = "This is the message"
    key = string_to_int(key)
    enc = encrypt(public_key, key)
    # Mallory intercepts the encrypted key
    print("intercepted encrypted key: ", enc)
    # Mallory alters encrypted key
    c_prime = enc * 0
    # Alice decrypts using the private key
    m_dec = decrypt(private_key, c_prime)
    print("decrypted malicious key: ", m_dec)
    # Alice uses malicious key to hash and encrypt using AES-CBC
    m_key = SHA256.new(str(m_dec).encode('utf-8')).digest()
    c0 = SHA_AES_encrypt(message, m_key, iv)
    print("encrypted message: ", c0)
    # Mallory decrypts c0 using her key
    m_key = SHA256.new(str(m_dec).encode('utf-8')).digest()
    message = SHA_AES_decrypt(c0, m_key, iv).decode('utf-8', "ignore")
    print("decrypted c0: ", message)

def M_attack():
    public_key, private_key = make_keys()
    m1 = 1234
    m2 = 5678
    m3 = m1 * m2
    m1_enc = encrypt(public_key, m1)
    m2_enc = encrypt(public_key, m2)
    m3_enc2 = encrypt(public_key, m3)
    m3_enc = m1_enc * m2_enc
    m3_dec = decrypt(private_key, m3_enc)
    m3_dec2 = decrypt(private_key, m3_enc2)
    if m3_dec == m3_dec2:
        print("valid signature!")
    else:
        print("invalid signature")
if __name__ == '__main__':
    print("RSA SIMULATION\n")
    RSA_simulation()
    print("\nRSA MITM SIMULATION\n")
    RSA_MITM_simulation()
    print("\nM3 SIMULATION\n")
    M_attack()
