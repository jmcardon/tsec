---
layout: docs
number: 2
title: "Message Digests"
---

# Hashing 

### Note: 

This has been beaten to death everywhere, but please do not use
these for Password Hashing. We provide [Password Hashers](/tsec/docs/passwordhashers.html) 
to use for this purpose under the password hashers section.

## Usage

For `TSec`, we support MD5, SHA1, SHA256 and SHA512 hashing of byte arrays, as well as
hashing of byte streams (fs2 does this as well, but we simply provide the helper via the type.
As a matter of fact, our implementation is identical to the fs2 implementation for the JCA, but different
for libsodium)


```tut
  /** Imports */
  import cats.Id
  import cats.effect.{IO, Sync}
  import fs2._
  import tsec.common._
  import tsec.hashing.imports._ //For this example, we will use our byteutil helpers

  /**For direct byte pickling, use: */
  "hiHello".utf8Bytes.hash[SHA1]
  "hiHello".utf8Bytes.hash[SHA256]
  "hiHello".utf8Bytes.hash[SHA512]
  "hiHello".utf8Bytes.hash[MD5]

  /** Alternatively, use the algorithms directly
    * Note: For the JCA, while you _can_ interpret
    * into `IO` if you ever need to work in it, hashing
    * is essentially pure. Thus, interpreting into `Id` is not unsafe
    * in this case
    */
  SHA1.hash[Id]("hiHello".utf8Bytes)
  SHA256.hash[Id]("hiHello".utf8Bytes)
  /** Some Monad with a sync bound: **/
  SHA512.hash[IO]("hiHello".utf8Bytes)
  
  
  def hashPipeExample[F[_]: Sync](str: Stream[F, Byte]): Stream[F, Byte] = {
    str.through(SHA512.hashPipe[F])
  }
```

