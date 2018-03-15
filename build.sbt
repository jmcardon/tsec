import Dependencies._

name := "tsec"

scalaVersion := "2.12.4"

lazy val scalacOpts = scalacOptions := Seq(
  "-unchecked",
  "-feature",
  "-deprecation",
  "-encoding",
  "utf8",
  "-Ywarn-adapted-args",
  "-Ywarn-inaccessible",
  "-Ywarn-unused:imports",
  "-Ywarn-nullary-override",
  "-Ypartial-unification",
  "-language:higherKinds",
  "-language:implicitConversions"
)

lazy val micrositeSettings = Seq(
  libraryDependencies += Libraries.gitHub4s,
  micrositeName := "TSec",
  micrositeBaseUrl := "/tsec",
  micrositeDescription := "A Type-Safe General Cryptography Library on the JVM",
  micrositeAuthor := "Jose Cardona",
  micrositeHomepage := "https://jmcardon.github.io/tsec/",
  micrositeGithubOwner := "jmcardon",
  micrositeGithubRepo := "tsec",
  micrositeDocumentationUrl := "/tsec/docs/symmetric.html",
  micrositeGitterChannel := false,
  micrositePushSiteWith := GitHub4s,
  micrositeGithubToken := sys.env.get("GITHUB_TOKEN")
)

lazy val commonSettings = Seq(
  libraryDependencies ++= Seq(
    Libraries.cats,
    Libraries.catsEffect,
    Libraries.scalaTest,
    Libraries.scalaCheck,
    Libraries.commonsCodec,
    Libraries.fs2IO
  ),
  organization in ThisBuild := "io.github.jmcardon",
  scalaVersion in ThisBuild := "2.12.4",
  fork in test := true,
  parallelExecution in test := false,
  addCompilerPlugin("org.spire-math" %% "kind-projector" % "0.9.5"),
  version in ThisBuild := "0.0.1-M9",
  scalacOpts
)

lazy val benchSettings = Seq(
  resolvers += "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots",
  libraryDependencies += Libraries.thyme
)

lazy val passwordHasherLibs = libraryDependencies ++= Seq(
  Libraries.sCrypt
)

lazy val bouncyLib = libraryDependencies += Libraries.BC

lazy val jwtCommonLibs = libraryDependencies ++= Seq(
  Libraries.circeCore,
  Libraries.circeGeneric,
  Libraries.circeGenericExtras,
  Libraries.circeParser
)

lazy val http4sDeps = libraryDependencies ++= Seq(
  Libraries.http4sdsl,
  Libraries.http4sServer,
  Libraries.http4sCirce
)

lazy val loggingLibs = libraryDependencies ++= Seq(
  Libraries.log4s
)

lazy val root = project
  .aggregate(
    common,
    messageDigests,
    cipherCore,
    jwtCore,
    symmetricCipher,
    mac,
    signatures,
    jwtMac,
    jwtSig,
    passwordHashers,
    http4s
  )

lazy val common = Project(id = "tsec-common", base = file("common"))
  .settings(commonSettings)
  .settings(publishSettings)

lazy val bouncyCastle = Project(id = "bouncy", base = file("bouncycastle"))
  .settings(commonSettings)
  .settings(bouncyLib)
  .settings(publishSettings)

lazy val passwordHashers = Project(id = "tsec-password", base = file("password-hashers"))
  .settings(commonSettings)
  .settings(passwordHasherLibs)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val cipherCore = Project(id = "tsec-cipher-core", base = file("cipher-core"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val symmetricCipher = Project(id = "tsec-symmetric-cipher", base = file("cipher-symmetric"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(cipherCore)

lazy val mac = Project(id = "tsec-mac", base = file("mac"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val messageDigests = Project(id = "tsec-md", base = file("message-digests"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val bouncyHash = Project(id = "tsec-hash-bouncy", base = file("hashing-bouncy"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(bouncyCastle)

lazy val signatures = Project(id = "tsec-signatures", base = file("signatures"))
  .settings(commonSettings)
  .settings(bouncyLib)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(bouncyCastle)

lazy val jwtCore = Project(id = "tsec-jwt-core", base = file("jwt-core"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(mac)
  .dependsOn(signatures)

lazy val jwtMac = Project(id = "tsec-jwt-mac", base = file("jwt-mac"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(mac)
  .dependsOn(jwtCore)

lazy val jwtSig = Project(id = "tsec-jwt-sig", base = file("jwt-sig"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(bouncyLib)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(jwtCore)
  .dependsOn(signatures)
  .dependsOn(messageDigests)
  .dependsOn(bouncyCastle)

lazy val bench = Project(id = "tsec-bench", base = file("bench"))
  .settings(commonSettings)
  .settings(benchSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(cipherCore)
  .dependsOn(symmetricCipher)
  .dependsOn(libsodium)
  .dependsOn(mac)
  .settings(publish := {})
  .enablePlugins(JmhPlugin)

lazy val examples = Project(id = "tsec-examples", base = file("examples"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(bouncyLib)
  .settings(passwordHasherLibs)
  .settings(http4sDeps)
  .dependsOn(
    symmetricCipher,
    mac,
    messageDigests,
    signatures,
    jwtMac,
    jwtSig,
    passwordHashers,
    http4s
  )
  .settings(publish := {})

lazy val http4s = Project(id = "tsec-http4s", base = file("tsec-http4s"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(passwordHasherLibs)
  .settings(http4sDeps)
  .settings(publishSettings)
  .settings(loggingLibs)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(
    symmetricCipher,
    mac,
    messageDigests,
    passwordHashers,
    jwtMac
  )

lazy val libsodium = Project(id = "tsec-libsodium", base = file("tsec-libsodium"))
  .settings(commonSettings)
  .settings(
    libraryDependencies ++= Seq(
      Libraries.fs2IO
    )
  )
  .settings(loggingLibs)
  .dependsOn(common % "compile->compile;test->test")

lazy val microsite = Project(id = "microsite", base = file("docs"))
  .settings(commonSettings)
  .settings(micrositeSettings)
  .enablePlugins(MicrositesPlugin)
  .enablePlugins(TutPlugin)
  .dependsOn(
    common,
    messageDigests,
    cipherCore,
    jwtCore,
    symmetricCipher,
    mac,
    signatures,
    jwtMac,
    jwtSig,
    passwordHashers,
    http4s,
    examples
  )

lazy val publishSettings = Seq(
  homepage := Some(url("https://github.com/jmcardon/tsec")),
  licenses := Seq("MIT" -> url("https://opensource.org/licenses/MIT")),
  scmInfo := Some(ScmInfo(url("https://github.com/jmcardon/tsec"), "scm:git:git@github.com:jmcardon/tsec.git")),
  autoAPIMappings := true,
  apiURL := None,
  bintrayRepository := "tsec",
  pomExtra :=
    <developers>
    <developer>
      <id>jmcardon</id>
      <name>Jose Cardona</name>
      <url>https://github.com/jmcardon/</url>
    </developer>
    <developer>
      <id>rsoeldner</id>
      <name>Robert Soeldner</name>
      <url>https://github.com/rsoeldner/</url>
    </developer>
  </developers>
)
