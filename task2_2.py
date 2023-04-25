import random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


def diffie_hellman():
    # Hardcode q and a
    q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
    a = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

    # Mallory tampers with the generator of a.
    a = 1

    # Generate random Xa and Xb within q. Xa is Alice's, Xb is Bob's
    Xa = random.randint(0,q)
    Xb = random.randint(0,q)
    # Calculate Ya and Yb. Ya is Alice's, Yb is Bob's
    Ya = pow(a,Xa,q)
    Yb = pow(a,Xb,q)

    # This is where Bob would send Yb to Alice, and Alice would send Ya to Bob.

    # Alice and Bob calculate their keys using the other's transmitted Y value. These should be the same!
    sa = pow(Yb,Xa,q)
    sb = pow(Ya,Xb,q)

    print("Alice's key: " + str(sa))
    print("Bob's key: " + str(sb))

    # Alice and Bob both hash their keys.
    ka = SHA256.new(str(sa).encode('utf-8')).digest()
    kb = SHA256.new(str(sb).encode('utf-8')).digest()

    print("\nAlice's key: " + str(ka))
    print("Bob's key: " + str(kb))

    print("Checking if ka and kb are the same... " + str(ka == kb))

    m0 = "Hello Bob, this is Alice."
    m1 = "Hello Alice, this is Bob."

    ciphera = AES.new(ka, AES.MODE_ECB)
    cipherb = AES.new(kb, AES.MODE_ECB)

    # Pad messages to be a multiple of 16 bytes
    m0 = m0 + " " * (16 - len(m0) % 16)
    m1 = m1 + " " * (16 - len(m1) % 16)

    c0 = ciphera.encrypt(bytes(m0, 'utf-8'))
    c1 = cipherb.encrypt(bytes(m1, 'utf-8'))

    print("\nBob received: " + str(c0))
    print("Alice received: " + str(c1))

    decrypta = AES.new(ka, AES.MODE_ECB)
    decryptb = AES.new(kb, AES.MODE_ECB)

    decrypteda = decrypta.decrypt(c1)
    decryptedb = decryptb.decrypt(c0)
    print("\nAlice decrypted: " + str(decrypteda))
    print("Bob decrypted: " + str(decryptedb))

    print("Checking if Alice and Bob's decrypted messages match pre-encryption... " + str(decrypteda == bytes(m1, 'utf-8')) + " " + str(decryptedb == bytes(m0, 'utf-8')))

    # However, Mallory is very easily able to decrypt these messages, as she can predict the key!
    # a is q, and q to some power mod q is still 0.
    km = SHA256.new(str(0).encode('utf-8')).digest()
    decryptm = AES.new(km, AES.MODE_ECB)
    decryptedm0 = decryptm.decrypt(c0)
    decryptedm1 = decryptm.decrypt(c1)
    print("\nMallory decrypted: " + str(decryptedm0) + " and " + str(decryptedm1))
    print("Checking if Mallory's decrypted messages match pre-encryption... " + str(
        decryptedm0 == bytes(m0, 'utf-8')) + " " + str(decryptedm1 == bytes(m1, 'utf-8')))

if __name__ == "__main__":
    diffie_hellman()