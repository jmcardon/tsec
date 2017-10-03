import sbt.{Def, _}
import Keys._

object Dependencies {

  object Versions {
    val circeV        = "0.9.0-M1"
    val catsV         = "1.0.0-MF"
    val catsEffV      = "0.4"
    val shapelessV    = "2.3.2"
    val thymeV        = "0.1.2-SNAPSHOT"
    val bouncyCastleV = "1.52"
    val jBCryptV      = "0.4.1"
    val sCryptV       = "1.4.0"
    val scalaTestV    = "3.0.1"
    val http4sV       = "0.18.0-M1"
  }

  object Libraries {
    val cats               = "org.typelevel"      %% "cats-core"            % Versions.catsV
    val shapeless          = "com.chuusai"        %% "shapeless"            % Versions.shapelessV
    val catsEffect         = "org.typelevel"      %% "cats-effect"          % Versions.catsEffV
    val jBCrypt            = "de.svenkubiak"      % "jBCrypt"               % Versions.jBCryptV
    val sCrypt             = "com.lambdaworks"    % "scrypt"                % Versions.sCryptV
    val scalaTest          = "org.scalatest"      %% "scalatest"            % Versions.scalaTestV % "test"
    val BC                 = "org.bouncycastle"   % "bcprov-jdk15on"        % Versions.bouncyCastleV
    val thyme              = "com.github.ichoran" %% "thyme"                % Versions.thymeV
    val circeCore          = "io.circe"           %% "circe-core"           % Versions.circeV
    val circeGeneric       = "io.circe"           %% "circe-generic"        % Versions.circeV
    val circeGenericExtras = "io.circe"           %% "circe-generic-extras" % Versions.circeV
    val circeParser        = "io.circe"           %% "circe-parser"         % Versions.circeV
    val http4sdsl          = "org.http4s"         %% "http4s-dsl"           % Versions.http4sV
  }

}
