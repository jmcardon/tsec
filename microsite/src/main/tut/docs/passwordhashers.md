---
layout: docs
number: 3
title: "Password Hashers"
---

## Password Hashers

For password hashers, you have three options: BCrypt, SCrypt and HardenedSCrypt 
(Which is basically scrypt but with much more secure parameters, but a lot slower).

SCrypt is recommended over BCrypt, as it improves over the memory-hardness of BCrypt.

```tut:silent
  import tsec.common._
  import tsec.passwordhashers._
  import tsec.passwordhashers.imports._
  val bcryptHash: BCrypt                 = "hiThere".hashPassword[BCrypt]
  val scryptHash: SCrypt                 = "hiThere".hashPassword[SCrypt]
  val hardenedScryptHash: HardenedSCrypt = "hiThere".hashPassword[HardenedSCrypt]
```

To Validate, you can check against a hash!

```tut:silent
  val check: Boolean = "hiThere".checkWithHash[BCrypt](bcryptHash)
```

Note: Since these password types are checked, you must coerce to the proper type
for compile-time verification, before you check:

```tut
  /*
  To Cast a hash to a plain string
   */
  bcryptHash.asString
  /*
  To cast a hash to a plain string
   */
  "hi".toStringRepr[BCrypt]
```