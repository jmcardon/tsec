---
layout: home
title:  "Motivation"
section: "crypto"
position: 3
---

## Motivation

TSec began as a desire to improve on what the JCA provides. While the JCA provides well tested,
secure algorithms, it suffers from being incredibly cumbersome to use. As an example, let's encrypt
something using AES-GCM:

```tut
import javax.crypto.{Cipher, KeyGenerator, SecretKey}

val keyGenerator: KeyGenerator = KeyGenerator.getInstance("AES") //Stringly typed
keyGenerator.init(192) //Any way to get this standard constant without setting it yourself? Also mutates!
val secretKey: SecretKey = keyGenerator.generateKey() //We have no information about what type of key this was

val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding") //Stringly Typed. also unsafe. May throw an exception.
cipher.init(Cipher.ENCRYPT_MODE, secretKey) //Encrypt mode is an int. May throw an exception. Also mutates!

val toEncrypt: Array[Byte] = "Hello".getBytes("UTF-8") 
val encrypted: Array[Byte] = cipher.doFinal(toEncrypt) //We have no information about 
```

Can you catch the mistake here? It's easy to overlook, but we do not have a reference to the IV (Initialization Vector) used,
thus we have no way to ever decrypt this if we forgot to retrieve it!

On top of this, outside of these local strings, we have no information carried by the objects about the encryption used,
key type used, and whatnot, which could all be useful at compile time. Feed it a wrong length key, this throws an exception!

TSec was made to improve on this. We provide types where the JCA does not, as well as we provide helpers to propagate 
all the encryption type information the JCA does not, so you can rip out a few hairs at compile time, not when you have to hotfix 
in production.

The same thing, in TSec, plus decryption:

```tut
import tsec.common._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._

val toEncrypt = "Hello".utf8Bytes
val onlyEncrypt: Either[CipherError, String] = for {
  instance  <- DefaultAuthEncryptor.instance //Instances are unsafe! Some JVMs may not have particular instances  
  key       <- DefaultAuthEncryptor.keyGen.generateKey() //Generate our key
  encrypted <- instance.encrypt(PlainText(toEncrypt), key) //Encrypt our message
  decrypted <- instance.decrypt(encrypted, key)
} yield decrypted.content.toUtf8String // "hi hello welcome to tsec!"
```