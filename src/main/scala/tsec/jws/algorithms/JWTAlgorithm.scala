package tsec.jws.algorithms

import java.nio.charset.StandardCharsets
import cats.effect.IO
import org.apache.commons.codec.binary.Base64
import shapeless.{::, HNil}
import tsec.mac.MacKey
import tsec.mac.instance._
import tsec.mac.core.MacSigningKey
import javax.crypto.{SecretKey => JSecretKey}
import com.softwaremill.tagging.@@
import tsec.mac.core.MacPrograms



sealed trait JWTAlgorithm[A, K[_]] {
  val jwtRepr: String

  def sign(content: String, key: K[A]): IO[String]
}

object JWTAlgorithm {
  def fromString(alg: String) = alg match {
    case HS256.jwtRepr => Some(HS256)
    case HS384.jwtRepr => Some(HS384)
    case HS512.jwtRepr => Some(HS512)
      //While we work on signatures, this can be none.
    case _ => None
  }
}

abstract class JWTMacAlgo[A: MacTag](implicit gen: MacPrograms.MacAux[A]) extends JWTAlgorithm[A, λ[A => MacSigningKey[MacKey[A]]]] {

  protected val signer: JMac[A] = JMac[A]()

  def sign(content: String, key: MacSigningKey[MacKey[A]]): IO[String] =
    signer
      .sign(content.getBytes(StandardCharsets.US_ASCII), key)
      .map(s => Base64.encodeBase64URLSafeString(gen.to(s).head))
}

case object HS256 extends JWTMacAlgo[HMACSHA256]{
  val jwtRepr: String = "HS256"
}

case object HS384 extends JWTMacAlgo[HMACSHA384]{
  val jwtRepr: String = "HS384"
}

case object HS512 extends JWTMacAlgo[HMACSHA512]{
  val jwtRepr: String = "HS512"
}

case object NoAlg extends JWTAlgorithm[NoSigningAlgorithm, Option]{
  val jwtRepr: String = "none"

  def sign(content: String, key: Option[NoSigningAlgorithm]): IO[String] = IO.pure(content)
}
/*
TODO: Assym signatures

case object RS256
case object RS384
case object RS512
*/