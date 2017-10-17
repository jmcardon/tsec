---
layout: docs
number: 7
title: "Digital Signatures"
---

# Digital Signatures

### Note: Signatures depends on the bouncy castle JCA Security provider. You will get a no such provider if it s not installed

For digital signatures, we support [almost all algorithms in the JCA](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature),
except for the <digest>with<encryption> style. 

## Examples

```tut
import tsec.common._
import tsec.signature.imports._
import cats.effect.{IO, Sync}

val toSign                               = "hiThere!".utf8Bytes
val instance: JCASigner[SHA256withECDSA] = JCASigner[SHA256withECDSA]
val sig: Either[Throwable, Boolean] = for {
  keyPair   <- SHA256withECDSA.generateKeyPair
  signed    <- instance.sign(toSign, keyPair.privateKey)
  verified  <- instance.verifyKI(toSign, signed, keyPair.publicKey) //Verify with the particular instance
  verified2 <- instance.verifyK(toSign, signed, keyPair.publicKey) //Or directly with arrays
} yield verified2

val instancePure: JCASignerPure[IO, SHA256withRSA] = JCASignerPure[IO, SHA256withRSA] //JCASignerPure will take any F[_]: Sync
val ioSign: IO[Boolean] = for {
  keyPair   <- Sync[IO].fromEither(SHA256withRSA.generateKeyPair)
  signed    <- instancePure.sign(toSign, keyPair.privateKey)
  verified  <- instancePure.verifyKI(toSign, signed, keyPair.publicKey)
  verified2 <- instancePure.verifyK(toSign, signed, keyPair.publicKey)
} yield verified2
```