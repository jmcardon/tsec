---
layout: docs
number: 7
title: "Digital Signatures"
---

# Digital Signatures

### Note: Signatures depends on the bouncy castle JCA Security provider. You will get a no such provider if it s not installed

For digital signatures, we support [almost all algorithms in the JCA](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature),
except for the <digest>with<encryption> style. 

The default `JCASigner` interprets into any `F[_]: Sync` from `cats-effect`.

## Examples

```tut:silent
  import tsec.common._
  import tsec.signature._
  import tsec.signature.jca._
  import cats.effect.Sync
  import cats.syntax.all._

  val toSign: Array[Byte] = "hiThere!".utf8Bytes

  /** Signature Example:
    */
  def pureSign[F[_]](implicit F: Sync[F]): F[(CryptoSignature[SHA256withRSA], Boolean)] =
    for {
      keyPair  <- SHA256withRSA.generateKeyPair[F]
      signed   <- SHA256withRSA.sign[F](toSign, keyPair.privateKey)
      verified <- SHA256withRSA.verifyBool[F](toSign, signed, keyPair.publicKey)
    } yield (signed, verified)

  /*
  Signature example with Either
   */
  val sig: Either[Throwable, Boolean] = for {
    keyPair <- SHA256withECDSA.generateKeyPair[SigErrorM]
    signed  <- SHA256withECDSA.sign[SigErrorM](toSign, keyPair.privateKey)
    verified <- SHA256withECDSA
      .verifyBool[SigErrorM](toSign, signed, keyPair.publicKey) //Verify with the particular instance
  } yield verified
```