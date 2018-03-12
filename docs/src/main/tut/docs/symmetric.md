---
layout: docs
number: 1
title: "Symmetric Ciphers"
---

# Symmetric Ciphers

### Important note:
For 256-bit key sizes, you will have to install the
Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy
    
You can get it [here](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)
    
You can refer to [this](https://stackoverflow.com/questions/41580489/how-to-install-unlimited-strength-jurisdiction-policy-files) for installation help 
    
Alternatively, if you are using a package manager like aptitude and have the java8 repositories on your machine,
you can install oracle-java8-unlimited-jce-policy
   
For debian-like distros:
Follow the instructions [here](http://tipsonubuntu.com/2016/07/31/install-oracle-java-8-9-ubuntu-16-04-linux-mint-18)
then use: `sudo apt-get install oracle-java8-unlimited-jce-policy`

## Introduction

For symmetric ciphers, we provide a low level as well as a high-level api construction.

Symmetric ciphers, as an introduction, have the following basic properties, for all non-empty m (as,  if a message is
empty, you're not encrypting anything and c = m):
```
 E(K, m) = c
 D(K, c) = m
 D(K, E(K, m)) = m
 
 Where:
    E: Encryption function
    D: Decryption function
    K: Some symmetric key
    m: Some message, or plainText
    c: Some ciphertext
```

However, in practice, block ciphers (and most secure stream ciphers like Salsa20) require a nonce as well
(called an initialization vector for block ciphers). As such, we need to either provide it explicitly, or
implicitly in our cipher construction. TSec provides such an implicit construction using `IvStrategy`.

## Usage

These are the imports you will need for basic usage:

```tut:silent
  import tsec.common._
  import tsec.cipher.symmetric.core._
  import tsec.cipher.symmetric.imports._
  import cats.effect.IO
```

In tsec, we provide a few default constructions for simple AES encryption:
`AES/CTR` and `AES/CBC`. For Authenticated encryption, 
we provide an `AES/GCM` construction.

To be able to generate initialization vectors for a particular cipher, you must either
have an implicit `IvStrategy[A]`(where A is the algorithm type, i.e `AES128GCM`) in scope, or pass it explicitly,
or use it to generate a nonce of the right size:


```tut
  val toEncrypt = "hi hello welcome to tsec".utf8Bytes

  implicit val ctrStrategy: IvGen[IO, AES128CTR] = AES128CTR.defaultIvStrategy[IO]

  val onlyEncrypt: IO[String] = AES128CTR.genEncryptor[IO].flatMap(
      implicit instance =>
        for {
          key       <- AES128CTR.generateKey[IO] //Generate our key
          encrypted <- AES128CTR.encrypt[IO](PlainText(toEncrypt), key) //Encrypt our message
          decrypted <- AES128CTR.decrypt[IO](encrypted, key)
        } yield decrypted.toUtf8String
    ) // "hi hello welcome to tsec!"

  /** You can also turn it into a singular array with the IV concatenated at the end */
  val onlyEncrypt2: IO[String] = AES128CTR.genEncryptor[IO].flatMap(
      implicit instance =>
        for {
          key       <- AES128CTR.generateKey[IO]                        //Generate our key
          encrypted <- AES128CTR.encrypt[IO](PlainText(toEncrypt), key) //Encrypt our message
          array = encrypted.toConcatenated
          from      <- IO.fromEither(AES128CTR.ciphertextFromConcat(array))
          decrypted <- AES128CTR.decrypt[IO](from, key)
        } yield decrypted.toUtf8String
    ) // "hi hello welcome to tsec!"
```

For authenticated encryption and decryption

```tut
  implicit val gcmstrategy = AES128GCM.defaultIvStrategy[IO]

  val aad = AAD("myAdditionalAuthenticationData".utf8Bytes)
  val encryptAAD: IO[String] = AES128GCM.genEncryptor[IO].flatMap(
      implicit instance =>
        for {
          key       <- AES128GCM.generateKey[IO]                                    //Generate our key
          encrypted <- AES128GCM.encryptWithAAD[IO](PlainText(toEncrypt), key, aad) //Encrypt
          decrypted <- AES128GCM.decryptWithAAD[IO](encrypted, key, aad)            //Decrypt
        } yield decrypted.toUtf8String
    ) // "hi hello welcome to tsec!"
```

Finally, For more advanced usage, i.e you know which cipher you want specifically, you must import 
both padding as well as the primitive package.

Note: This is not recommended. Use at your own risk.

```tut
  /** For more advanced usage, i.e you know which cipher you want specifically, you must import padding
    * as well as the low level package
    *
    * this is not recommended, but useful for.. science!
    *
    */
  import tsec.cipher.common.padding._
  import tsec.cipher.symmetric.imports.primitive._
  val desStrategy = JCAIvGen.random[IO, DES]

  val advancedUsage: IO[String] = for {
    instance  <- JCAPrimitiveCipher.sync[IO, DES, CBC, PKCS7Padding]()
    key       <- DES.generateKey[IO]
    iv        <- desStrategy.genIv
    encrypted <- instance.encrypt(PlainText(toEncrypt), key, iv) //Encrypt our message, with our auth data
    decrypted <- instance.decrypt(encrypted, key) //Decrypt our message: We need to pass it the same AAD
  } yield decrypted.toUtf8String
```