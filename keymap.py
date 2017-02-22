import random

ch = [ i for i in range(ord("0"), ord("9") + 1) ] + [ i for i in range(ord("a"), ord("f") + 1) ]

keymap = [ "".join([ chr(random.choice(ch)) for j in range(16) ]) for i in range(64) ]

print(keymap)
