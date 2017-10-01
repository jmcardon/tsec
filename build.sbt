import Dependencies._

name := "fucc"

version := "0.0.1"

val circeV        = "0.9.0-M1"
val catsV         = "1.0.0-MF"
val catsEffV      = "0.4"
val shapelessV    = "2.3.2"
val thymeV        = "0.1.2-SNAPSHOT"
val bouncyCastleV = "1.52"
val jBCryptV      = "0.4.1"
val sCryptV       = "1.4.0"
val scalaTestV    = "3.0.1"

scalaVersion := "2.12.3"

lazy val scalacOpts = scalacOptions := Seq(
  "-unchecked",
  "-feature",
  "-deprecation",
  "-encoding",
  "utf8",
  "-Ywarn-adapted-args", // Warn if an argument list is modified to match the receiver.
  "-Ywarn-inaccessible", // Warn about inaccessible types in method signatures.
  "-Ywarn-nullary-override", // Warn when non-nullary overrides nullary, e.g. def foo() over def foo.
  "-Ypartial-unification",
  "-language:higherKinds",
  "-language:implicitConversions"
)

lazy val commonSettings = Seq(
  libraryDependencies ++= Seq(
    Libraries.cats,
    Libraries.catsEffect,
    Libraries.shapeless,
    Libraries.scalaTest
  ),
  organization in ThisBuild := "io.github.jmcardon",
  scalaVersion in ThisBuild := "2.12.3",
  fork in test := true,
  parallelExecution in test := false,
  addCompilerPlugin("org.spire-math" %% "kind-projector" % "0.9.4"),
  version in ThisBuild := "0.0.1",
  scalacOpts
)

lazy val benchSettings = Seq(
  resolvers += "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots",
  libraryDependencies += Libraries.thyme
)

lazy val passwordHasherLibs = libraryDependencies ++= Seq(
  Libraries.sCrypt,
  Libraries.jBCrypt
)

lazy val signatureLibs = libraryDependencies += Libraries.BC

lazy val jwtCommonLibs = libraryDependencies ++= Seq(
  Libraries.circeCore,
  Libraries.circeGeneric,
  Libraries.circeGenericExtras,
  Libraries.circeParser
)

lazy val root = Project(id = "tsec", base = file("."))
  .settings(commonSettings)
  .aggregate(
  symmetricCipher,
    mac,
    messageDigests,
    signatures,
    jwtMac,
    jwtSig,
    passwordHashers
  )

lazy val common = Project(id = "tsec-common", base = file("core")).settings(commonSettings)

lazy val passwordHashers = Project(id = "tsec-password", base = file("password-hashers"))
  .settings(commonSettings)
  .settings(passwordHasherLibs)
  .dependsOn(common % "compile->compile;test->test")

lazy val cipherCore = Project(id = "cipher-core", base = file("cipher-core"))
  .settings(commonSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val symmetricCipher = Project(id = "tsec-symmetric-cipher", base = file("cipher-symmetric"))
  .settings(commonSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(cipherCore)

lazy val mac = Project(id = "tsec-mac", base = file("mac"))
  .settings(commonSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val messageDigests = Project(id = "tsec-messageDigests", base = file("message-digests"))
  .settings(commonSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val signatures = Project(id = "tsec-signatures", base = file("signatures"))
  .settings(commonSettings)
  .settings(signatureLibs)
  .dependsOn(common % "compile->compile;test->test")

lazy val jwtCore = Project(id = "tsec-jwt-core", base = file("jwt-core"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(mac)
  .dependsOn(signatures)

lazy val jwtMac = Project(id = "tsec-jwt-mac", base = file("jwt-mac"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(mac)
  .dependsOn(jwtCore)

lazy val jwtSig = Project(id = "tsec-jwt-sig", base = file("jwt-sig"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(signatureLibs)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(jwtCore)
  .dependsOn(signatures)
  .dependsOn(messageDigests)

lazy val bench = Project(id = "tsec-bench", base = file("bench"))
  .settings(commonSettings)
  .settings(benchSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(cipherCore)
  .dependsOn(symmetricCipher)
