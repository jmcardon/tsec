package tsec.jwt.algorithms

import java.nio.charset.StandardCharsets

import cats.effect.IO
import org.apache.commons.codec.binary.Base64
import shapeless.{::, HNil}
import tsec.mac.MacKey
import javax.crypto.{SecretKey => JSecretKey}

import com.softwaremill.tagging.@@
import tsec.mac.core.MacPrograms
import tsec.mac.core.MacSigningKey
import tsec.mac.instance._

import scala.reflect.ClassTag

sealed trait JWTAlgorithm[A, K[_]] {
  val jwtRepr: String

  def sign(content: String, key: MacSigningKey[K[A]]): IO[String]
}

abstract class JCASymmetricSign[A: MacTag](implicit gen: MacPrograms.MacAux[A]) extends JWTAlgorithm[A, MacKey] {

  protected val signer: JMac[A] = JMac[A]()

  def sign(content: String, key: MacSigningKey[MacKey[A]]): IO[String] =
    signer
      .sign(content.getBytes(StandardCharsets.US_ASCII), key)
      .map(s => Base64.encodeBase64URLSafeString(gen.to(s).head))
}

case object HS256 extends JCASymmetricSign[HMACSHA256]{
  val jwtRepr: String = "HS256"
}

case object HS384 extends JCASymmetricSign[HMACSHA384]{
  val jwtRepr: String = "HS384"
}

case object HS512 extends JCASymmetricSign[HMACSHA512]{
  val jwtRepr: String = "HS512"
}

case object RS256
case object RS384
case object RS512