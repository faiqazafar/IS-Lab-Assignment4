# =========================
#   Simple RSA Algorithm
#   (No external libraries)
# =========================

# ----- Helper: Greatest Common Divisor -----
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# ----- Helper: Extended Euclidean Algorithm -----
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


# ----- Modular Multiplicative Inverse -----
def mod_inverse(e, phi):
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise Exception("No modular inverse")
    return x % phi


# ============ RSA KEY GENERATION ============
def generate_keys():
    # Small primes for learning
    p = 101
    q = 113

    n = p * q                      # Modulus
    phi = (p - 1) * (q - 1)        # Euler Totient

    # Choose e: 1 < e < phi and gcd(e, phi) = 1
    e = 17
    if gcd(e, phi) != 1:
        raise Exception("e and phi not co-prime")

    # Compute private key exponent d
    d = mod_inverse(e, phi)

    return (e, n), (d, n)


# ============ ENCRYPTION ============
def encrypt_message(message, public_key):
    e, n = public_key
    encrypted = [(ord(ch) ** e) % n for ch in message]
    return encrypted


# ============ DECRYPTION ============
def decrypt_message(cipher, private_key):
    d, n = private_key
    decrypted = "".join([chr((c ** d) % n) for c in cipher])
    return decrypted


# ============ DEMO TEST ============
public_key, private_key = generate_keys()

name = "amna"   # change to your own name if needed
print("\nOriginal Message:", name)

cipher = encrypt_message(name, public_key)
print("Encrypted Numbers:", cipher)

plain = decrypt_message(cipher, private_key)
print("Decrypted Message:", plain)

print("\nPublic Key =", public_key)
print("Private Key =", private_key)

# ============================
#   Task 2 - RSA with PyCryptodome
# ============================

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# ----------- Generate 2048-bit RSA Key Pair -----------
key_pair = RSA.generate(2048)

public_key = key_pair.publickey()
private_key = key_pair

print("\n----- Generated RSA Keys (2048-bit) -----")
print("Public Key:", public_key.export_key().decode())
print("Private Key:", private_key.export_key().decode())


# ----------- Input Message from User -----------
message = input("\nEnter a message to encrypt: ").encode()


# ----------- Encrypt using Public Key -----------
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(message)

print("\nEncrypted Message (HEX):")
print(binascii.hexlify(ciphertext).decode())


# ----------- Decrypt using Private Key -----------
decrypt_cipher = PKCS1_OAEP.new(private_key)
decrypted_msg = decrypt_cipher.decrypt(ciphertext)

print("\nDecrypted Message:")
print(decrypted_msg.decode())

# ================================
#   Task 3 - Digital Signature RSA
# ================================

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ------------- Generate RSA Key Pair (2048-bit) -------------
key_pair = RSA.generate(2048)
public_key = key_pair.publickey()
private_key = key_pair


print("\n----- RSA Key Pair Generated -----")
print("Public Key:", public_key.export_key().decode())
print("Private Key:", private_key.export_key().decode())

# ------------- Original Message -------------
message = "Data Security Assignment - RSA Digital Signature"
print("\nOriginal Message:", message)

# Create SHA256 hash
hash_obj = SHA256.new(message.encode())

# Sign the hashed message using PRIVATE KEY
signature = pkcs1_15.new(private_key).sign(hash_obj)
print("\nDigital Signature (Hex):", signature.hex())

# ------------- Verification Step -------------
try:
    pkcs1_15.new(public_key).verify(hash_obj, signature)
    print("\nVerification Successful: Signature is VALID")
except (ValueError, TypeError):
    print("\nVerification Failed!!")


# ------------- Tamper the Message -------------
fake_message = "Data Security Assignment - RSA Digital Signatures"  # small change (extra 's')
print("\nModified Message:", fake_message)

# New hash for modified message
fake_hash = SHA256.new(fake_message.encode())

# Verify again with original signature (should fail)
try:
    pkcs1_15.new(public_key).verify(fake_hash, signature)
    print("Verification Successful: Signature is VALID (Unexpected!)")
except (ValueError, TypeError):
    print("Verification Failed: Message has been modified ❌")
