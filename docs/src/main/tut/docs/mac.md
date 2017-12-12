---
layout: docs
number: 4
title: "Message Authentication Code"
---

## Message Authentication Code

Example message authentication: Note, will use byteutils


```tut:silent
 import tsec.common._
 import tsec.mac.imports._
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
      macValue  <- JCAMac.sign(toMac, key)                   //Generate our MAC bytes
      verified  <- JCAMac.verify(toMac, macValue, key)       //Verify a byte array with a signed, typed instance
      verified2 <- JCAMac.verifyArrays(toMac, macValue, key) //Alternatively, use arrays directly
    } yield verified
```


To use the _impure_ version:
```tut:silent
  val `mac'd`: Either[Throwable, Boolean] = for {
    key       <- HMACSHA256.generateKey()                        //Generate our key.
    macValue  <- JCAMacImpure.sign(toMac, key)                   //Generate our MAC bytes
    verified  <- JCAMacImpure.verify(toMac, macValue, key)       //Verify a byte array with a signed, typed instance
    verified2 <- JCAMacImpure.verifyArrays(toMac, macValue, key) //Alternatively, use arrays directly
  } yield verified
```

