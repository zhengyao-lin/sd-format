import rsa
import util
import time

(pub, priv) = rsa.newkeys(1024)

print(priv)
print(pub)

msg = "hello, my name is rod"

clk = time.clock()

crypto = rsa.encrypt(msg, pub)
print(util.to_hex(crypto), len(crypto))
print(rsa.decrypt(crypto, priv))

print(time.clock() - clk)

sign = rsa.sign(msg, priv, "SHA-1")
rsa.verify(msg, sign, pub)
