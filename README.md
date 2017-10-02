```
________________________________________  
\__    ___/   _____/\_   _____/\_   ___ \ 
  |    |  \_____  \  |    __)_ /    \  \/ 
  |    |  /        \ |        \\     \____
  |____| /_______  //_______  / \______  /
                 \/         \/         \/ 
```
# TSEC: A type-safe, functional, general purpose security and cryptography library.

Latest Release: 0.0.1-M1

Contains:
- Symmetric Encryption
- Asymmetric Encryption
- Message Digests
- Message Authentication (MAC)
- Password Hashing BCrypt and SCrypt
- Digital Signatures (RSA with SHA, ECDSA with SHA and DSA with SHA)
- JWT (JWS with JWT serialization), both MAC and Signature (JWA spec is a WIP)

For the current progress, please refer to the [roadmap](https://github.com/jmcardon/tsec/issues/7)


V0.0.1-M1 is here for scala 2.12+ and Cats 1.0.0-MF!

To get started, if you are on sbt 0.13.16+, add

```scala
resolvers += Resolver.bintrayRepo("jmcardon", "tsec")
```

or

```scala
resolvers += "jmcardon at bintray" at "https://dl.bintray.com/jmcardon/tsec"
```

| Name                  | Description                                              |
| -----                 | ----------                                               |
| tsec-common           | Common crypto utilities                                  |
| tsec-password         | Password hashers: BCrypt and Scrypt                      |
| tsec-symmetric-cipher | Symmetric encryption utilities!                          |
| tsec-mac              | Message Authentication                                   |
| tsec-signatures       | Digital signatures                                       |
| tsec-messageDigests   | Message Digests (Hashing)                                |
| tsec-jwt-mac          | JWT implementation for Message Authentication signatures |
| tsec-jwt-sig          | JWT implementation for Digital signatures                |

Examples coming soon.

To include any of these packages in your project use:

```scala
val tsecV = "0.0.1-M1"
 libraryDependencies ++= Seq(
 "io.github.jmcardon" %% "tsec-common" % tsecV,
 "io.github.jmcardon" %% "tsec-password" % tsecV,
 "io.github.jmcardon" %% "tsec-symmetric-cipher" % tsecV,
 "io.github.jmcardon" %% "tsec-mac" % tsecV,
 "io.github.jmcardon" %% "tsec-signatures" % tsecV,
 "io.github.jmcardon" %% "tsec-messageDigests" % tsecV,
 "io.github.jmcardon" %% "tsec-jwt-mac" % tsecV,
 "io.github.jmcardon" %% "tsec-jwt-sig" % tsecV
)
```