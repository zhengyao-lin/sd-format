import rsa
import util

(pub, priv) = rsa.newkeys(1024)

print(priv)

msg = "hello"

crypto = rsa.encrypt(msg, pub)
print(util.to_hex(crypto), len(crypto))
print(rsa.decrypt(crypto, priv))
