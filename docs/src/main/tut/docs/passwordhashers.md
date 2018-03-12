---
layout: docs
number: 3
title: "Password Hashers"
---

## Password Hashers

For password hashers on the JCA, you have three options: BCrypt, SCrypt and HardenedSCrypt 
(Which is basically scrypt but with much more secure parameters, but a lot slower).

SCrypt is recommended over BCrypt, as it improves over the memory-hardness of BCrypt. Over both,
Argon2 from the libsodium package is preferred.

Password hashing involves nonce generation, thus, it uses java's `SecureRandom` for the JCA, and 
libsodium's own random function for the `libsodium` module. Thus,
it is inherently side effecting. 

Preferably, if possible, you want to receive your password as an `Array[Byte]` or
`Array[Char]` without ever storing a string. TSec handles this case first and foremost.

[This](https://stackoverflow.com/questions/8881291/why-is-char-preferred-over-string-for-passwords) stack overflow
link explains this quite clearly, but, in a nutshell, Strings cannot be wiped by anything other than GC, thus they will
be in memory until then, which poses a vulnerability. The main problem is that this allows access to plaintext passwords
if the attacker has direct access to memory, which is more dangerous than just accessing the hashes.

That said, it's more of a precaution: If an attacker has direct memory access to your application, you most likely
have much bigger problems to worry about (Compromised and vulnerable network/ports and things open to the internet). 
So while it may be grasping at straws a bit, A security library should aim for the most secure default.

So for the default case of char arrays, we can hash into any `Sync[F]` as such:

```tut:silent
  import cats.effect.IO
  import tsec.passwordhashers.core._
  import tsec.passwordhashers.imports._
  val pass: Array[Char] = Array('h', 'e', 'l', 'l', 'o', 'w', 'o', 'r', 'l', 'd')
  val bestbcryptHash: IO[PasswordHash[BCrypt]]                 = BCrypt.hashpw[IO](pass)
  val bestscryptHash: IO[PasswordHash[SCrypt]]                 = SCrypt.hashpw[IO](pass)
  val besthardenedScryptHash: IO[PasswordHash[HardenedSCrypt]] = HardenedSCrypt.hashpw[IO](pass)
```

The string case is the same.
```tut:silent
  val bcryptHash: IO[PasswordHash[BCrypt]]                 = BCrypt.hashpw[IO]("hiThere")
  val scryptHash: IO[PasswordHash[SCrypt]]                 = SCrypt.hashpw[IO]("hiThere")
  val hardenedScryptHash: IO[PasswordHash[HardenedSCrypt]] = HardenedSCrypt.hashpw[IO]("hiThere")
```

To Validate, you can check against a hash! Naturally, if it returns false, it was hashed incorrectly.

```tut:silent
  val checkProgram: IO[Boolean] = for {
    hash  <- bcryptHash
    check <- BCrypt.checkpw[IO]("hiThere", hash)
  } yield check
```

Alternatively, if purity is your enemy, you can use the unsafe methods. Do note: 
these may throw an exception for malformed input when checking password, and in `hashPwUnsafe`, we generate
a nonce using `SecureRandom`, thus it is side effecting.

```tut:silent
  val unsafeHash: PasswordHash[BCrypt] = BCrypt.hashpwUnsafe("hiThere")
  val unsafeCheck: Boolean             = BCrypt.checkpwUnsafe("hiThere", unsafeHash)
```
