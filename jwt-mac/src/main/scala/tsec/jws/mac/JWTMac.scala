package tsec.jws.mac

import java.time.Instant

import cats.Eq
import cats.effect.Sync
import cats.syntax.all._
import tsec.common._
import tsec.jws.{JWSJWT, JWSSerializer}
import tsec.jwt.JWTClaims
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.mac._
import tsec.mac.jca.{MacErrorM, MacSigningKey}

sealed abstract case class JWTMac[A](header: JWSMacHeader[A], body: JWTClaims, signature: MAC[A])
    extends JWSJWT[A, MAC] {
  def toEncodedString(implicit hs: JWSSerializer[JWSMacHeader[A]]): String =
    hs.toB64URL(header) + "." + JWTClaims.toB64URL(body) + "." + signature.toB64UrlString

  def id = body.jwtId

  def ==(other: JWTMac[A]) =
    header == other.header &&
      body == other.body &&
      signature.toB64String == other.signature.toB64String

  override def equals(obj: Any): Boolean = obj match {
    case j: JWTMac[A] => ==(j)
    case _            => false
  }
}

object JWTMac {
  private[tsec] def buildToken[A](header: JWSMacHeader[A], claims: JWTClaims, signature: MAC[A]): JWTMac[A] =
    new JWTMac[A](header, claims, signature) {}

  /** Methods abstracted over F[_] */
  def build[F[_], A: JWTMacAlgo](
      claims: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[F, A], F: Sync[F]): F[JWTMac[A]] = {
    val header = JWSMacHeader[A]
    generateSignature[F, A](header, claims, key).map(sig => JWTMac.buildToken[A](header, claims, sig))
  }

  def generateSignature[F[_], A: JWTMacAlgo](
      header: JWSMacHeader[A],
      body: JWTClaims,
      key: MacSigningKey[A]
  )(
      implicit s: JWSMacCV[F, A],
      me: Sync[F]
  ): F[MAC[A]] = s.sign(header, body, key)

  def generateSignature[F[_], A: JWTMacAlgo](body: JWTClaims, key: MacSigningKey[A])(
      implicit s: JWSMacCV[F, A],
      me: Sync[F]
  ): F[MAC[A]] = s.sign(JWSMacHeader[A], body, key)

  def buildToString[F[_], A: JWTMacAlgo](
      header: JWSMacHeader[A],
      body: JWTClaims,
      key: MacSigningKey[A],
  )(implicit s: JWSMacCV[F, A], me: Sync[F]): F[String] = s.signToString(header, body, key)

  def buildToString[F[_], A: JWTMacAlgo](
      body: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[F, A], me: Sync[F]): F[String] = s.signToString(JWSMacHeader[A], body, key)

  def verify[F[_], A: JWTMacAlgo](jwt: String, key: MacSigningKey[A])(
      implicit s: JWSMacCV[F, A],
      F: Sync[F]
  ): F[Boolean] = F.delay(Instant.now()).flatMap(s.verify(jwt, key, _))

  def verifyAndParse[F[_], A](jwt: String, key: MacSigningKey[A])(
      implicit s: JWSMacCV[F, A],
      F: Sync[F]
  ): F[JWTMac[A]] =
    F.delay(Instant.now()).flatMap(s.verifyAndParse(jwt, key, _))

  def verifyFromString[F[_], A: JWTMacAlgo](jwt: String, key: MacSigningKey[A])(
      implicit s: JWSMacCV[F, A],
      F: Sync[F]
  ): F[Boolean] = F.delay(Instant.now()).flatMap(s.verify(jwt, key, _))

  def verifyFromInstance[F[_], A: JWTMacAlgo](jwt: JWTMac[A], key: MacSigningKey[A])(
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      cv: JWSMacCV[F, A],
      F: Sync[F]
  ): F[Boolean] = F.delay(Instant.now()).flatMap(cv.verify(jwt.toEncodedString, key, _))

  def toEncodedString[F[_], A: JWTMacAlgo](
      jwt: JWTMac[A]
  )(implicit s: JWSMacCV[F, A], me: Sync[F]): String = s.toEncodedString(jwt)

  def parseUnverified[F[_], A: JWTMacAlgo](
      jwt: String
  )(implicit s: JWSMacCV[F, A], me: Sync[F]): F[JWTMac[A]] = s.parseUnverified(jwt)
}

object JWTMacImpure {

  implicit def eq[A]: Eq[JWTMac[A]] = new Eq[JWTMac[A]] {
    def eqv(x: JWTMac[A], y: JWTMac[A]): Boolean =
      x.header == y.header &&
        x.body == y.body &&
        x.signature.toB64String == y.signature.toB64String
  }

  /** Default methods */
  def build[A: JWTMacAlgo](
      claims: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[MacErrorM, A]): MacErrorM[JWTMac[A]] =
    s.signAndBuild(JWSMacHeader[A], claims, key)

  /** Sign the header and the body with the given key, into a jwt object
    *
    * @param header the JWT header
    * @param body
    * @param key
    * @param s
    * @tparam A
    * @return
    */
  def generateSignature[A: JWTMacAlgo](header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A])(
      implicit s: JWSMacCV[MacErrorM, A]
  ): MacErrorM[MAC[A]] = s.sign(header, body, key)

  def generateSignature[A: JWTMacAlgo](body: JWTClaims, key: MacSigningKey[A])(
      implicit s: JWSMacCV[MacErrorM, A]
  ): MacErrorM[MAC[A]] =
    s.sign(JWSMacHeader[A], body, key)

  def buildToString[A: JWTMacAlgo](
      body: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[MacErrorM, A]): MacErrorM[String] = s.signToString(JWSMacHeader[A], body, key)

  def buildToString[A: JWTMacAlgo](
      header: JWSMacHeader[A],
      body: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[MacErrorM, A]): MacErrorM[String] = s.signToString(header, body, key)

  /** Verify the JWT
    *
    * @param jwt the JWT, as a string representation
    * @param key the signing key
    * @tparam A the signing algorithm
    * @return Signing output as a boolean or a MacError.
    *         Useful to detect any other errors aside from malformed input.
    */
  def verifyFromString[A: JWTMacAlgo](jwt: String, key: MacSigningKey[A])(
      implicit s: JWSMacCV[MacErrorM, A]
  ): MacErrorM[Boolean] = s.verify(jwt, key, Instant.now)

  def verifyFromInstance[A: JWTMacAlgo](jwt: JWTMac[A], key: MacSigningKey[A])(
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      cv: JWSMacCV[MacErrorM, A]
  ): MacErrorM[Boolean] = cv.verify(jwt.toEncodedString, key, Instant.now)

  def verifyAndParse[A](jwt: String, key: MacSigningKey[A])(implicit s: JWSMacCV[MacErrorM, A]): MacErrorM[JWTMac[A]] =
    s.verifyAndParse(jwt, key, Instant.now)

  def toEncodedString[A: JWTMacAlgo](
      jwt: JWTMac[A]
  )(implicit s: JWSMacCV[MacErrorM, A]): String = s.toEncodedString(jwt)

  def parseUnverified[A: JWTMacAlgo](
      jwt: String
  )(implicit s: JWSMacCV[MacErrorM, A]): MacErrorM[JWTMac[A]] = s.parseUnverified(jwt)
}
