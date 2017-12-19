##
## Basic crypto util for studying purpose
##
## Most of the simple func is for learning purpose and on purpose to be verbose 
##
## This is tested on Python 3.6
##
## @TODO: Replace all test cases with Unittest
## 
## 
import os
import sys
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
from Crypto.Hash import SHA256

from math import *


# just an alias for a easier to remember name
def byte2hex(b):
    return i2h(b) 

# a basic text padding func
# Input:
# msg: input msg to pad
# m : the divider of length of total output text with padding. e.g. AES is 16
# output: bytestring padded with bytes as per PKCS5 padding scheme 
# @TODO: check the big endian and little endian parameter
#
# Ref: https://www.cryptosys.net/pki/manpki/pki_paddingschemes.html 
#
def paddingBytes(msg,m=16):
    # the equation try to solve is:
    # (len(msg) + len(padding)) mod 16 == 0
    n = -len(msg) % m
    if n == 0:
        n = 1 # at least one dummy byte as reqd
    return msg.encode() + (n).to_bytes(1,byteorder='big')*n



# a basic text padding reoval func
# Input:
# text: input decrypted text with pad
# m : the divider of length of total output text with padding. e.g. AES is 16
def removePad(text,m=16):
    last = int.from_bytes(text[-1:], byteorder='big')
    # note: last should be less than 16
    return text[0:(len(text)-last)]

# extract 16 bytes iv from CBC cipher text
def extractCBC_IV(ct):
    return ct[0:16]


# read a file in bytes from the start of the file
def bytes_from_file(filename, chunksize=1024):
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(chunksize)
            if chunk:
                #for b in chunk:
                #    yield b
                yield chunk
            else:
                break

# read a file in bytes from the end of the file
# @NOTE: last byte is the shorter one
def bytes_from_file_rev(filename, chunksize=1024):
    with open(filename, "rb") as f:
        fend = f.seek(0,os.SEEK_END);
        pos = (fend // chunksize) * chunksize
        f.seek(pos);
        while pos >= 0:
            #print(pos)
            chunk = f.read(chunksize)
            pos -= chunksize
            if pos < 0:
                f.seek(0)
            else:
                f.seek(pos)
            if chunk:
                yield chunk
            else:
                break


# ref: https://stackoverflow.com/questions/16443185/reading-a-binary-file-on-backwards-using-python
def prettyPrintBytes(pos,b):
    b1 = b[:8]                  # first 8 bytes
    b2 = b[8:]                  # the rest
    s1 = ' '.join('{:02x}'.format(x) for x in b1)
    s2 = ' '.join('{:02x}'.format(x) for x in b2)
    print('{:08x}:'.format(pos), s1, '|', s2)


# This seems redundant, as .new() might not be required for consective call of .update()
# ref: https://www.dlitz.net/software/pycrypto/api/current/Crypto.Hash.hashalgo.HashAlgo-class.html#update
#
def hash(b):
    h = SHA256.new();
    h.update(b);
    return bytes.fromhex(h.hexdigest());

# keep this under your pillow: http://docs.python.org/library/index.html
# note: use "".join() to put the array into a long string again
def i2h(b):
    return "%0.2X" % b # don't use 0x prefix. "0x%0.2X" % n

# xor two byte strings of different lengths
# it returns an byte string
def xor(b1,b2):
    #l = min(len(b1),len(b2)) # I don't think I need this at all ...
    # note: zip returns the length of the shorter input
    tmp =  [ i2h(x ^ y) for (x,y) in zip(b1,b2)]
    return bytes.fromhex("".join(tmp)) 

# Ref: 
# Myths about /dev/urandom https://www.2uo.de/myths-about-urandom/
# Note: this key returns as a byte string
def random(size=16):
    return open("/dev/urandom","rb").read(size)

# input:
# key: byte string
# msg: string
# output: byte string
def encrypt(key, msg):
    return xor(key,msg.encode())

#
# input:
# key: byte string
# cipher: byte string
# output: string
def decrypt(key, cipher):
    return xor(key,cipher).decode()

#
# filter out the cipher text based on input criteria
#
def validRange(n):
    if (n >= 0x10 and n <= 0x19) or (n >= 0x41 and n <= 0x5A) or (n >=61 and n <= 0x7A):
        return n
    else:
        return 0xff


#
# GCD
# Ref: Number Theory and Cryptography
# https://www.coursera.org/learn/number-theory-cryptography
#
def gcd(a, b):
  assert a >= 0 and b >= 0 and a + b > 0

  while a > 0 and b > 0:
    if a >= b:
      a = a % b
    else:
      b = b % a

  return max(a, b)


#
# Extended GCD
# Ref: Number Theory and Cryptography
# https://www.coursera.org/learn/number-theory-cryptography
#
def extended_gcd(a, b):
  assert a >= b and b >= 0 and a + b > 0

  if b == 0:
    d, x, y = a, 1, 0
  else:
    (d, p, q) = extended_gcd(b, a % b)
    x = q
    y = p - q * (a // b)

  assert a % d == 0 and b % d == 0
  assert d == a * x + b * y
  return (d, x, y)

#
# LCM
# Ref: Number Theory and Cryptography
# https://www.coursera.org/learn/number-theory-cryptography
#
def lcm(n, m):
    if n >= m:
        (d, x, y) = extended_gcd(n,m)
    else:
        (d, x, y) = extended_gcd(m,n)
    return (n * m) / d

#
# Integer Division
# Ref: Number Theory and Cryptography
# https://www.coursera.org/learn/number-theory-cryptography
#
def divide(a, b, n):
    assert n > 1 and a > 0 and gcd(a, n) == 1
    
    if a >= n:
        (d, p, q) = extended_gcd(a,n)
    else:
        (d, q, p) = extended_gcd(n,a)
  
    # solving diophantine
    c = 1 # constant  
    tmp = c // d
    s = tmp * p # this is the multiplicative inv of a mod n
    t = tmp * q
 
    x = (b * s) % n
  
    # return the number x s.t. x = b / a (mod n) and 0 <= x <= n-1.
    return x

#
# Chinese Remainder Theorem
# Ref: Number Theory and Cryptography
# https://www.coursera.org/learn/number-theory-cryptography
#
# TODO: Extend this to n equations
#
def crt(n1, r1, n2, r2):
    if n1 >= n2:
        (d, s, t) = extended_gcd(n1, n2)
    else:
        (d, t, s) = extended_gcd(n2, n1)

    #print(n1 * s * r1)
    #print(n2* t * r2)

    n = n1 * s * r2 + n2 * t * r1

    #print(n)

    return n % (n1 * n2)

# NOTE:
# add this to the code
# a^n == ( a^(n % (p-1)  ) ) mod p
def exp2k(b,e,m):
    k = int(log2(e))
    c = b % m
    for i in range(0,k):
        c = (c * c) % m
    return c

#
# Fast Modular Exponentiation
# Ref: Number Theory and Cryptography
# https://www.coursera.org/learn/number-theory-cryptography
#
def FastModExp(b, e, m):
    bNum = "{0:b}".format(e)
    l = len(bNum)
    c = 1
    for i in range(0,l):
        if bNum[i] == '1':
            ee = 2 ** (l-i-1)
            c = (c * exp2k(b,ee,m)) % m
        else:
            pass

    return c


#
# Test cases 
#
def test1():
    print("================")
    print("test case #1 ...")
    print("================")

    # generate a random key
    key = random() # for testing  
    print("Generated random key:")
    print(">> " + str(key.hex()))

    # now the fun part, encript the message
    # try a simple one first
    m1 = "Hello World"
    print("Simple plain text:")
    print(">> " + m1)

    print("encrypt the message with the key:")
    c1 = encrypt(key, m1)
    print(">> " + c1.hex())

    print("let try to recover the msg with xor'ing with the key again:")
    msg = xor(key,c1)
    print(">> " + msg.hex())

    print("let's try to recover the key now:")
    keyR = xor(c1,m1.encode())
    print(">> " + keyR.hex())

    print("try the decrypt function:")
    print(">> " + decrypt(key,c1))

#
# test array of messages
#
def test2():
    print("================")
    print("test case #2 ...")
    print("================")
   
    m1 = "Hello World"
    m2 = "What the fox say"
    k = random(20)

    marr = [m1,m2]

    print("let's encrypt the whole array of messages")
    carr = [encrypt(k,m) for m in marr]
    print(carr)

    print("let's decrypt the whole array of ciphers")
    parr = [decrypt(k,c) for c in carr]
    print(parr)

#
#
#
def test3():
    pt = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ct = pt.encode()

    print("pt: " + pt)
    print("ct: " + ct.hex())

    space = i2h(32)
    print("space: " + space)

    print("xor [0-9a-zA-Z] with space 0x20")
    tmp =  [ i2h(h ^ bytes.fromhex(space)[0])  for h in pt.encode()]
    print(tmp)

#
#
#
def test4():
    m1 = "Hello World"
    m2 = "What the fox say"
    m3 = "Where am I going"

    k = random()
   
    print("k   : " + k.hex())

    c1 = encrypt(k,m1)
    c2 = encrypt(k,m2)
    c3 = encrypt(k,m3)

    print("c1  : " + c1.hex())
    print("c2  : " + c2.hex())
    print("c3  : " + c3.hex())
    
    m1m2 = xor(c1,c2)
    m1m3 = xor(c1,c3)
    m2m3 = xor(c2,c3)

    print("m1m2: " + m1m2.hex())
    print("m1m3: " + m1m3.hex())
    print("m2m3: " + m2m3.hex())

    return 0





#
# Main assignment work here ...
#
def main():
    test1()
    test2()
    return 0

# required for linux ...
if __name__ == '__main__':
    main()
