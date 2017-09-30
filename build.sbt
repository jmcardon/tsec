name := "fucc"

version := "0.0.1"

val circeV     = "0.9.0-M1"
val catsV      = "1.0.0-MF"
val catsEffV   = "0.4"
val shapelessV = "2.3.2"

scalaVersion := "2.12.3"

resolvers += "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots"

libraryDependencies ++= Seq(
  "org.typelevel"           %% "cats-core"            % catsV,
  "com.chuusai"             %% "shapeless"            % shapelessV,
  "org.typelevel"           %% "cats-effect"          % catsEffV,
  "commons-codec"           % "commons-codec"         % "1.10",
  "de.svenkubiak"           % "jBCrypt"               % "0.4.1",
  "com.lambdaworks"         % "scrypt"                % "1.4.0",
  "org.scalatest"           %% "scalatest"            % "3.0.1" % "test",
  "org.bouncycastle"        % "bcprov-jdk15on"        % "1.52",
  "com.github.ichoran"      %% "thyme"                % "0.1.2-SNAPSHOT",
  "io.circe"                %% "circe-core"           % circeV,
  "io.circe"                %% "circe-generic"        % circeV,
  "io.circe"                %% "circe-generic-extras" % circeV,
  "io.circe"                %% "circe-parser"         % circeV
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
