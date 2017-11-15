---
layout: home
title:  "Home"
section: "home"
technologies:
 - first: ["Scala", "sbt-microsites plugin is completely written in Scala"]
 - second: ["SBT", "sbt-microsites plugin uses SBT and other sbt plugins to generate microsites easily"]
 - third: ["Jekyll", "Jekyll allows for the transformation of plain text into static websites and blogs."]
---

# TSec - Tagless Security

**TSec** Is a type-safe general cryptography library on the JVM.

[![Join the chat at https://gitter.im/tsecc/Lobby](https://badges.gitter.im/tsecc/Lobby.svg)](https://gitter.im/tsecc/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/jmcardon/tsec.svg?branch=master)](https://travis-ci.org/jmcardon/tsec)
[ ![Latest Version](https://api.bintray.com/packages/jmcardon/tsec/tsec-common/images/download.svg) ](https://bintray.com/jmcardon/tsec/tsec-common/_latestVersion)


For the current progress, please refer to the [RoadMap](https://github.com/jmcardon/tsec/wiki).

For version changes and additions, including breaking changes, see either [release notes](https://github.com/jmcardon/tsec/releases)
or the [Version Changes](https://github.com/jmcardon/tsec/wiki/Version-Changes) page.

0.0.1-M4 is here for scala 2.12+ and Cats 1.0.0-RC1!

To get started, if you are on sbt 0.13.16+, add

```scala
resolvers += "jmcardon at bintray" at "https://dl.bintray.com/jmcardon/tsec"
```

or with the bintray plugin:

```scala
resolvers += Resolver.bintrayRepo("jmcardon", "tsec")
```


| Name                  | Description                                              | Examples |
| -----                 | ----------                                               | -------- |
| tsec-common           | Common crypto utilities                                  |          |
| tsec-password         | Password hashers: BCrypt and Scrypt                      | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/PasswordHashingExamples.scala)|
| tsec-symmetric-cipher | Symmetric encryption utilities!                          | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/SymmetricCipherExamples.scala)|
| tsec-mac              | Message Authentication                                   | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/MacExamples.scala)|
| tsec-signatures       | Digital signatures                                       | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/SignatureExamples.scala)|
| tsec-messageDigests   | Message Digests (Hashing)                                | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/MessageDigestExamples.scala)|
| tsec-jwt-mac          | JWT implementation for Message Authentication signatures | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/JWTMacExamples.scala)|
| tsec-jwt-sig          | JWT implementation for Digital signatures                | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/JWTSignatureExamples.scala)|
| tsec-http4s           | Http4s Request Authentication and Authorization          | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/http4sExamples/)|

To include any of these packages in your project use:

```scala
val tsecV = "0.0.1-M4"
 libraryDependencies ++= Seq(
 "io.github.jmcardon" %% "tsec-common" % tsecV,
 "io.github.jmcardon" %% "tsec-password" % tsecV,
 "io.github.jmcardon" %% "tsec-symmetric-cipher" % tsecV,
 "io.github.jmcardon" %% "tsec-mac" % tsecV,
 "io.github.jmcardon" %% "tsec-signatures" % tsecV,
 "io.github.jmcardon" %% "tsec-md" % tsecV,
 "io.github.jmcardon" %% "tsec-jwt-mac" % tsecV,
 "io.github.jmcardon" %% "tsec-jwt-sig" % tsecV,
 "io.github.jmcardon" %% "tsec-http4s" % tsecV
)
```

## Testing:

All tests can be run locally, but make sure you have the 
[Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)
installed for tests that use Keys larger than 128 bits. More information under [symmetric cipher](/tsec/docs/symmetric.html) in the docs.

## Inspirations:

[play-silhouette](https://github.com/mohiva/play-silhouette)

[JCA](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)

[Bouncy Castle](http://www.bouncycastle.org/)

[jwt-scala](https://github.com/pauldijou/jwt-scala)

## Big Thanks to:

[Robert Soeldner](https://github.com/rsoeldner) (Contributor)

[Edmund Noble](https://github.com/edmundnoble) (For the dank tagless)

[Fabio Labella](https://github.com/systemfw) (For the great FP help)

[Christopher Davenport](https://github.com/ChristopherDavenport)(Contributor)

[Bjørn Madsen](https://github.com/aeons) (Contributor)

[Will Sargent](https://github.com/wsargent) (Security Discussions)