---
layout: docs
number: 2
title: "Message Digests"
---

# Hashing 

### Note: 

[This has been beaten to death everywhere](https://crackstation.net/hashing-security.htm), but please do not use
these for Password Hashing. We provide Password Hashers to use for this purpose under the password hashers section.

## Usage

For `TSec`, we support MD5, SHA1, SHA256 and SHA512 hashing of byte arrays.

To hash any arbitrary class, like String, you must supply an implicit `CryptoPickler[A]`.
As an example, you can use, for strings, the default string pickler, which serializes the string to utf-8 bytes
 A crypto pickler is simply a value class with a function T => Array[Bytes]. i.e:
`CryptoPickler[String](_.getBytes("UTF-8"))`
For strings, these are covered by our `CryptoPickler` companion object. That said, if you absolutely must serialize an object
and would like to hash it, [do _not_ use java serialization](https://www.darkreading.com/informationweek-home/why-the-java-deserialization-bug-is-a-big-deal/d/d-id/1323237?).



```tut
  import tsec.common._
  import tsec.messagedigests._
  import tsec.messagedigests.imports._ //For this example, we will use our byteutil helpers
  
  
  implicit val pickler: CryptoPickler[String] = CryptoPickler.stringPickle[UTF8]

  "hi".pickleAndHash[SHA256]

  /**For direct byte pickling, use: */
  "hiHello".utf8Bytes.hash[SHA1]
  "hiHello".utf8Bytes.hash[SHA256]
  "hiHello".utf8Bytes.hash[SHA512]
  "hiHello".utf8Bytes.hash[MD5]
```

