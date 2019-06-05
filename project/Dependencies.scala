import sbt._

object Dependencies {

  object Versions {
    val circeV        = "0.11.1"
    val catsV         = "1.6.1"
    val bouncyCastleV = "1.60"
    val sCryptV       = "1.4.0"
    val scalaTestV    = "3.0.7"
    val http4sV       = "0.20.1"
    val scalacheckV   = "1.14.0"
    val commonsCodecV = "1.12"
    val fs2Version    = "1.0.4"
    val log4sV        = "1.7.0"
  }

  object Libraries {
    val fs2                = "co.fs2"           %% "fs2-core"             % Versions.fs2Version
    val fs2IO              = "co.fs2"           %% "fs2-io"               % Versions.fs2Version
    val cats               = "org.typelevel"    %% "cats-core"            % Versions.catsV
    val sCrypt             = "com.lambdaworks"  % "scrypt"                % Versions.sCryptV
    val scalaTest          = "org.scalatest"    %% "scalatest"            % Versions.scalaTestV % "test"
    val BC                 = "org.bouncycastle" % "bcprov-jdk15on"        % Versions.bouncyCastleV
    val circeCore          = "io.circe"         %% "circe-core"           % Versions.circeV
    val circeGeneric       = "io.circe"         %% "circe-generic"        % Versions.circeV
    val circeGenericExtras = "io.circe"         %% "circe-generic-extras" % Versions.circeV
    val circeParser        = "io.circe"         %% "circe-parser"         % Versions.circeV
    val http4sdsl          = "org.http4s"       %% "http4s-dsl"           % Versions.http4sV
    val http4sServer       = "org.http4s"       %% "http4s-server"        % Versions.http4sV
    val http4sCirce        = "org.http4s"       %% "http4s-circe"         % Versions.http4sV % "test"
    val scalaCheck         = "org.scalacheck"   %% "scalacheck"           % Versions.scalacheckV % "test"
    val commonsCodec       = "commons-codec"    % "commons-codec"         % Versions.commonsCodecV
    val log4s              = "org.log4s"        %% "log4s"                % Versions.log4sV
  }

}
