from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

username = input("Enter username: ")

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

private_key = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()
)

public_key = key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

with open(f"{username}_private.pem", "wb") as f:
    f.write(private_key)

with open(f"{username}_public.pem", "wb") as f:
    f.write(public_key)

print("Keys generated.")
