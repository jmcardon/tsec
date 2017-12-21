import sbt.{Def, _}
import Keys._

object Dependencies {

  object Versions {
    val circeV        = "0.9.0-M3"
    val catsV         = "1.0.0-RC2"
    val catsEffV      = "0.6"
    val thymeV        = "0.1.2-SNAPSHOT"
    val bouncyCastleV = "1.58"
    val sCryptV       = "1.4.0"
    val scalaTestV    = "3.0.4"
    val http4sV       = "0.18.0-M6"
    val scalacheckV   = "1.13.4"
    val commonsCodecV = "1.11"
    val fs2Version    = "0.10.0-M10"
  }

  object Libraries {
    val fs2                = "co.fs2"             %% "fs2-core"             % Versions.fs2Version
    val fs2IO              = "co.fs2"             %% "fs2-io"               % Versions.fs2Version
    val cats               = "org.typelevel"      %% "cats-core"            % Versions.catsV
    val catsEffect         = "org.typelevel"      %% "cats-effect"          % Versions.catsEffV
    val sCrypt             = "com.lambdaworks"    % "scrypt"                % Versions.sCryptV
    val scalaTest          = "org.scalatest"      %% "scalatest"            % Versions.scalaTestV % "test"
    val BC                 = "org.bouncycastle"   % "bcprov-jdk15on"        % Versions.bouncyCastleV
    val thyme              = "com.github.ichoran" %% "thyme"                % Versions.thymeV
    val circeCore          = "io.circe"           %% "circe-core"           % Versions.circeV
    val circeGeneric       = "io.circe"           %% "circe-generic"        % Versions.circeV
    val circeGenericExtras = "io.circe"           %% "circe-generic-extras" % Versions.circeV
    val circeParser        = "io.circe"           %% "circe-parser"         % Versions.circeV
    val http4sdsl          = "org.http4s"         %% "http4s-dsl"           % Versions.http4sV
    val http4sServer       = "org.http4s"         %% "http4s-server"        % Versions.http4sV
    val http4sCirce        = "org.http4s"         %% "http4s-circe"         % Versions.http4sV % "test"
    val scalaCheck         = "org.scalacheck"     %% "scalacheck"           % Versions.scalacheckV % "test"
    val commonsCodec       = "commons-codec"      % "commons-codec"         % Versions.commonsCodecV
  }

}
