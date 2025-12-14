### Usage

```python
from gost-34.12-2015 import gost34122015

key = bytes.fromhex('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef')
message = bytes.fromhex('1122334455667700ffeeddccbbaa9988')

cipher = gost34122015(key)
ciphertext = cipher.encrypt(message)
print(ciphertext.hex())

decrypted = cipher.decrypt(ciphertext)
print(decrypted.hex())
```
