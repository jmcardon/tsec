```
________________________________________  
\__    ___/   _____/\_   _____/\_   ___ \ 
  |    |  \_____  \  |    __)_ /    \  \/ 
  |    |  /        \ |        \\     \____
  |____| /_______  //_______  / \______  /
                 \/         \/         \/ 
```
# [TSEC: A type-safe, functional, general purpose security and cryptography library.](https://jmcardon.github.io/tsec/)

[![Join the chat at https://gitter.im/tsecc/Lobby](https://badges.gitter.im/tsecc/Lobby.svg)](https://gitter.im/tsecc/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/jmcardon/tsec.svg?branch=master)](https://travis-ci.org/jmcardon/tsec)
[ ![Latest Version](https://api.bintray.com/packages/jmcardon/tsec/tsec-common/images/download.svg) ](https://bintray.com/jmcardon/tsec/tsec-common/_latestVersion)


### Latest Release: 0.0.1-M6

For the current progress, please refer to the [RoadMap](https://github.com/jmcardon/tsec/wiki)

For version changes and additions, including breaking changes, see either [release notes](https://github.com/jmcardon/tsec/releases)
or the [Version Changes](https://github.com/jmcardon/tsec/wiki/Version-Changes) page.

0.0.1-M6 is here for scala 2.12+ and Cats 1.0.0-RC1!

To get started, if you are on sbt 0.13.16+, add

```scala
resolvers += "jmcardon at bintray" at "https://dl.bintray.com/jmcardon/tsec"
```

or (with the sbt-bintray plugin)

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
| tsec-md               | Message Digests (Hashing)                                | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/MessageDigestExamples.scala)|
| tsec-jwt-mac          | JWT implementation for Message Authentication signatures | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/JWTMacExamples.scala)|
| tsec-jwt-sig          | JWT implementation for Digital signatures                | [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/JWTSignatureExamples.scala)|
| tsec-http4s           | Http4s Request Authentication and Authorization          | [here](https://github.com/jmcardon/tsec/tree/master/examples/src/main/scala/http4sExamples)|

To include any of these packages in your project use:

```scala
val tsecV = "0.0.1-M6"
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

## IMPORTANT NOTE: About higher than 128-bit encryption key sizes on the JCA!
## This applies to you if you are using any AES algorithms with higher than 128-bit key sizes
For 256-bit key sizes, you will have to install the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy

You can get it at: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

You can refer to:
https://stackoverflow.com/questions/41580489/how-to-install-unlimited-strength-jurisdiction-policy-files

Alternatively, if you are using a package manager like aptitude and have the java8 repositories on your machine,
you can install oracle-java8-unlimited-jce-policy 
  
For debian-like distros:
Follow the instructions [here](http://tipsonubuntu.com/2016/07/31/install-oracle-java-8-9-ubuntu-16-04-linux-mint-18)
then use:

 `sudo apt-get install oracle-java8-unlimited-jce-policy` 
 
## Big Thank you to our contributors (direct or indirect):
[Robert Soeldner](https://github.com/rsoeldner) (Contributor/Maintainer)

[Christopher Davenport](https://github.com/ChristopherDavenport)(Contributor/Maintainer)

[Harrison Houghton](https://github.com/ChristopherDavenport)(Contributor/Maintainer)

[Bjørn Madsen](https://github.com/aeons) (Contributor)

[André Rouél](https://github.com/before)(Contributor)

[Edmund Noble](https://github.com/edmundnoble) (For the dank tagless)

[Fabio Labella](https://github.com/systemfw) (For the great FP help)

[Will Sargent](https://github.com/wsargent) (Security Discussions)
