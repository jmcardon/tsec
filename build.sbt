name := "fucc"

version := "0.0.1"

val circeV = "0.8.0"

scalaVersion := "2.12.3"

resolvers += "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots"

libraryDependencies ++= Seq(
  "org.typelevel" %% "cats" % "0.9.0",
  "com.chuusai" %% "shapeless" % "2.3.2",
  "org.typelevel" %% "cats-effect" % "0.3",
  "commons-codec" % "commons-codec" % "1.10",
  "com.softwaremill.common" %% "tagging" % "2.1.0",
  "de.svenkubiak" % "jBCrypt" % "0.4.1",
  "com.lambdaworks" % "scrypt" % "1.4.0",
  "org.scalatest" %% "scalatest" % "3.0.1" % "test",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.52",
  "com.github.ichoran" %% "thyme" % "0.1.2-SNAPSHOT",
  "io.circe" %% "circe-core" % circeV,
  "io.circe" %% "circe-generic" % circeV,
  "io.circe" %% "circe-generic-extras" % circeV,
  "io.circe" %% "circe-parser" % circeV
)

addCompilerPlugin("org.spire-math" %% "kind-projector" % "0.9.4")

scalacOptions := Seq(
  "-unchecked",
  "-feature",
  "-deprecation",
  "-encoding",
  "utf8",
  "-Ypartial-unification",
  "-language:higherKinds",
  "-language:implicitConversions"
)
