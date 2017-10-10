package tsec.jws.mac

import cats.{Eq, Monad, MonadError}
import tsec.common._
import tsec.jws.{JWSJWT, JWSSerializer, JWSSignature}
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.mac.imports.{MacErrorM, MacSigningKey}
import cats.syntax.functor._
import io.circe.Decoder
import io.circe.parser.decode
import tsec.jwt.JWTClaims

sealed abstract case class JWTMac[A](header: JWSMacHeader[A], body: JWTClaims, signature: JWSSignature[A])
    extends JWSJWT[A] {
  def toEncodedString(implicit hs: JWSSerializer[JWSMacHeader[A]]): String =
    hs.toB64URL(header) + "." + JWTClaims.toB64URL(body) + "." + signature.toB64UrlString

  def id = body.jwtId

  def ==(other: JWTMac[A]) =
    header == other.header &&
    body == other.body &&
    signature.toB64String == other.signature.toB64String

  override def equals(obj: Any): Boolean = obj match {
    case j: JWTMac[A] => ==(j)
    case _ => false
  }
}

object JWTMac {

  implicit def eq[A]: Eq[JWTMac[A]] = new Eq[JWTMac[A]]{
    def eqv(x: JWTMac[A], y: JWTMac[A]): Boolean =
      x.header == y.header &&
    x.body == y.body &&
    x.signature.toB64String == y.signature.toB64String
  }

  /** Default methods */
  def build[A: ByteEV: JWTMacAlgo](
      claims: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[MacErrorM, A]): MacErrorM[JWTMac[A]] =
    s.signAndBuild(JWSMacHeader[A], claims, key)

  private[tsec] def buildToken[A](header: JWSMacHeader[A], claims: JWTClaims, signature: JWSSignature[A]): JWTMac[A] =
    new JWTMac[A](header, claims, signature) {}

  /** Sign the header and the body with the given key, into a jwt object
    *
    * @param header the JWT header
    * @param body
    * @param key
    * @param s
    * @tparam A
    * @return
    */
  def generateSignature[A: ByteEV: JWTMacAlgo](header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A])(
      implicit s: JWSMacCV[MacErrorM, A]
  ): MacErrorM[JWSSignature[A]] = s.sign(header, body, key)

  def generateSignature[A: ByteEV: JWTMacAlgo](body: JWTClaims, key: MacSigningKey[A])(
      implicit s: JWSMacCV[MacErrorM, A]
  ): MacErrorM[JWSSignature[A]] =
    s.sign(JWSMacHeader[A], body, key)

  def buildToString[A: ByteEV: JWTMacAlgo](
      body: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[MacErrorM, A]): MacErrorM[String] = s.signToString(JWSMacHeader[A], body, key)

  def buildToString[A: ByteEV: JWTMacAlgo](
      header: JWSMacHeader[A],
      body: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[MacErrorM, A]): MacErrorM[String] = s.signToString(header, body, key)

  /** Verify the JWT
    *
    * @param jwt the JWT, as a string representation
    * @param key the signing key
    * @tparam A the signing algorithm
    * @return Signing output as a boolean or a MacError. Useful to detect any other errors aside from maformed input
    */
  def verifyFromString[A: ByteEV: JWTMacAlgo](jwt: String, key: MacSigningKey[A])(
      implicit s: JWSMacCV[MacErrorM, A]
  ): MacErrorM[Boolean] = s.verify(jwt, key)

  def verifyFromInstance[A: ByteEV: JWTMacAlgo](jwt: JWTMac[A], key: MacSigningKey[A])(
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      cv: JWSMacCV[MacErrorM, A]
  ): MacErrorM[Boolean] = cv.verify(jwt.toEncodedString, key)

  def verifyAndParse[A](jwt: String, key: MacSigningKey[A])(implicit s: JWSMacCV[MacErrorM, A]): MacErrorM[JWTMac[A]] =
    s.verifyAndParse(jwt, key)

  def toEncodedString[A: ByteEV: JWTMacAlgo](
      jwt: JWTMac[A]
  )(implicit s: JWSMacCV[MacErrorM, A]): String = s.toEncodedString(jwt)
}

object JWTMacM {

  /** Methods abstracted over F[_] */
  def build[F[_], A: ByteEV: JWTMacAlgo](
      claims: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[F, A], me: MonadError[F, Throwable]): F[JWTMac[A]] = {
    val header = JWSMacHeader[A]
    generateSignature[F, A](header, claims, key).map(sig => JWTMac.buildToken[A](header, claims, sig))
  }

  def generateSignature[F[_], A: ByteEV: JWTMacAlgo](
      header: JWSMacHeader[A],
      body: JWTClaims,
      key: MacSigningKey[A]
  )(
      implicit s: JWSMacCV[F, A],
      me: MonadError[F, Throwable]
  ): F[JWSSignature[A]] = s.sign(header, body, key)

  def generateSignature[F[_], A: ByteEV: JWTMacAlgo](body: JWTClaims, key: MacSigningKey[A])(
      implicit s: JWSMacCV[F, A],
      me: MonadError[F, Throwable]
  ): F[JWSSignature[A]] = s.sign(JWSMacHeader[A], body, key)

  def buildToString[F[_], A: ByteEV: JWTMacAlgo](
      header: JWSMacHeader[A],
      body: JWTClaims,
      key: MacSigningKey[A],
  )(implicit s: JWSMacCV[F, A], me: MonadError[F, Throwable]): F[String] = s.signToString(header, body, key)

  def buildToString[F[_], A: ByteEV: JWTMacAlgo](
      body: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[F, A], me: MonadError[F, Throwable]): F[String] = s.signToString(JWSMacHeader[A], body, key)

  def verify[F[_], A: ByteEV: JWTMacAlgo](jwt: String, key: MacSigningKey[A])(
      implicit s: JWSMacCV[F, A],
      me: MonadError[F, Throwable]
  ): F[Boolean] = s.verify(jwt, key)

  def verifyAndParse[F[_], A](jwt: String, key: MacSigningKey[A])(
      implicit s: JWSMacCV[F, A],
      me: MonadError[F, Throwable]
  ): F[JWTMac[A]] =
    s.verifyAndParse(jwt, key)

  def verifyFromString[F[_], A: ByteEV: JWTMacAlgo](jwt: String, key: MacSigningKey[A])(
      implicit s: JWSMacCV[F, A],
      me: MonadError[F, Throwable]
  ): F[Boolean] = s.verify(jwt, key)

  def verifyFromInstance[F[_], A: ByteEV: JWTMacAlgo](jwt: JWTMac[A], key: MacSigningKey[A])(
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      cv: JWSMacCV[F, A],
      me: MonadError[F, Throwable]
  ): F[Boolean] = cv.verify(jwt.toEncodedString, key)

  def toEncodedString[F[_], A: ByteEV: JWTMacAlgo](
      jwt: JWTMac[A]
  )(implicit s: JWSMacCV[F, A], me: MonadError[F, Throwable]): String = s.toEncodedString(jwt)
}
