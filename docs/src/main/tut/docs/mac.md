---
layout: docs
number: 4
title: "Message Authentication Code"
---

## Message Authentication Code

Example message authentication: Note, will use byteutils


```tut:silent
 import tsec.common._
 import tsec.mac.jca._
```

Default Pure version with usage of cats effect `Sync[F]`
```tut:silent
  val toMac: Array[Byte] = "hi!".utf8Bytes

  import cats.syntax.all._
  import cats.effect.Sync

  /** For Interpetation into any F */
  def `mac'd-pure`[F[_]: Sync]: F[Boolean] =
    for {
      key       <- HMACSHA256.generateLift[F]                //Generate our key.
      macValue  <- HMACSHA256.sign[F](toMac, key)                   //Generate our MAC bytes
      verified  <- HMACSHA256.verify[F](toMac, macValue, key)       //Verify a byte array with a signed, typed instance
      verified2 <- HMACSHA256.verifyArrays[F](toMac, macValue, key) //Deprecated
    } yield verified
```


To use the _impure_ version:
```tut:silent
  val `mac'd`: Either[Throwable, Boolean] = for {
    key       <- HMACSHA256.generateKey[MacErrorM]                        //Generate our key.
    macValue  <- HMACSHA256.sign[MacErrorM](toMac, key)                   //Generate our MAC bytes
    verified  <- HMACSHA256.verify[MacErrorM](toMac, macValue, key)       //Verify a byte array with a signed, typed instance
    verified2 <- HMACSHA256.verifyArrays[MacErrorM](toMac, macValue, key) //Deprecated
  } yield verified
```

