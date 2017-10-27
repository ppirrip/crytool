# crytool

A collection of basic functions for crypto related work in python, based on the assignments from Coursea's Cryptography I.

## Basic byte level operation

This is such a common operation in crypto related coding so here is the basic cheat sheet.

For a simple ascii string:
```python
msg = 'hello world'
```
For the byte string representation of the `msg`:
```python
bmsg = msg.encode() # or just b'hello world'
```

To examine the byte string in hex format:
```python
bmsgArr = [crytool.byte2hex(b) for b in bmsg]
```

To read a hex string into a byte array:
```python
bstr = bytes.fromhex('32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904')
```
To generate a random byte array using [urandom](https://www.2uo.de/myths-about-urandom/):
```python
r16bytes = crytool.random(16)
```
or with the [*pyCrypto*](https://www.dlitz.net/software/pycrypto/) library,

```python
from Crypto import Random
r16bytes = Random.new().read(AES.block_size) 
```

To xor two byte arrays of the same length:
```python
pt = b'Sixteen byte key' # or 'Sixteen byte key'.encode()
key = crytool.random( len(pt) )
ct = crytool.xor(pt,key) # stream cipher
```
To output the byte string in hex representation:
```python
ct.hex() # or "".join([crytool.byte2hex(b) for b in ct])
# e.g. '77020C898AA1E8EBA5019CD916D03962'
```
To convert an integer to byte(s):
```python
n = 0xAE # some integer
n.to_bytes(1,byteorder='big')     # convert 0xAE to a byte
n.to_bytes(5,byteorder='big')     # convert 0xAE into a byte string of 5 bytes representing 0xAE
n.to_bytes(1,byteorder='big')*5   # output a byte string of byte 0xAE repeating 5 times
```

To combine (i.e. reduce) a list of bytes to one long byte string:
```python
import functools
a = [n.to_bytes(1,byteorder='big') for n in range(0,5)] # output: [b'\x00', b'\x01', b'\x02', b'\x03', b'\x04']
functools.reduce(lambda x, y: x + y, a) # output: b'\x00\x01\x02\x03\x04'
```

*more to come later*





