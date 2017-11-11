package tsec.csrf

import java.security.MessageDigest
import java.time.Clock

import cats.data.{Kleisli, OptionT}
import cats.effect.Sync
import tsec.common.ByteEV
import tsec.mac.imports.{JCAMacPure, MacTag}
import tsec.common._
import tsec.mac._
import tsec.mac.imports._
import cats.syntax.all._
import org.http4s.{Cookie, Request, Response, Status}
import org.http4s.util.CaseInsensitiveString
import tsec.authentication.cookieFromRequest

/** Middleware to avoid Cross-site request forgery attacks.
  * More info on CSRF at: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
  *
  * This middleware is modeled after the double submit cookie pattern:
  * https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie
  *
  * The idea in the first place, is, on authentication, to use the `embedNew` method or
  * `withNewToken` middleware in your request. i.e, your user logs in, then they are sent, on top of their credentials
  * token, the CSRF value in the cookie.
  *
  * Then, on every authenticated endpoint, that's either modifying sensitive data via POST or retrieving
  * sensitive data via GET, to send the value stored in the csrf cookie in the header specified by the name in
  * `headerName`. An attacker, due to the Same-Origin policy, will be unable to reproduce this value in a custom header,
  * thus it will forbid his request
  *
  * @param headerName your csrf header name
  * @param cookieName the csrf cookie name
  * @param key the csrf signing key
  * @param clock clock used as a nonce
  */
final class TSecCSRF[F[_], A: MacTag: ByteEV] private[tsec] (
    key: MacSigningKey[A],
    val headerName: String,
    val cookieName: String,
    val tokenLength: Int,
    clock: Clock
)(implicit mac: JCAMacPure[F, A], F: Sync[F]) {

  def isEqual(s1: String, s2: String): Boolean =
    MessageDigest.isEqual(s1.utf8Bytes, s2.utf8Bytes)

  def signToken(string: String): F[CSRFToken] =
    for {
      millis <- F.delay(clock.millis())
      joined = string + "-" + millis
      signed <- mac.sign(joined.utf8Bytes, key)
    } yield CSRFToken(joined + "-" + signed.asByteArray.toB64String)

  def generateToken: F[CSRFToken] =
    signToken(CSRFToken.generateHexBase(tokenLength))

  /**
    * Extract a signed token
    */
  def extractRaw(token: CSRFToken): OptionT[F, String] =
    token.split("-", 3) match {
      case Array(raw, nonce, signed) =>
        OptionT(
          mac
            .sign((raw + "-" + nonce).utf8Bytes, key)
            .map(
              f => if (MessageDigest.isEqual(f.asByteArray, signed.base64Bytes)) Some(raw) else None
            )
        )
      case _ =>
        OptionT.none
    }

  def checkEqual(token1: CSRFToken, token2: CSRFToken): OptionT[F, Boolean] =
    for {
      raw1 <- extractRaw(token1)
      raw2 <- extractRaw(token2)
    } yield isEqual(raw1, raw2)

  def validate: CSRFMiddleware[F] =
    req =>
      Kleisli { r: Request[F] =>
        for {
          c1       <- cookieFromRequest[F](cookieName, r)
          c2       <- OptionT.fromOption[F](r.headers.get(CaseInsensitiveString(headerName)).map(_.value))
          raw1     <- extractRaw(CSRFToken(c1.content))
          raw2     <- extractRaw(CSRFToken(c2))
          res      <- if (isEqual(raw1, raw2)) req(r) else OptionT.none
          newToken <- OptionT.liftF(signToken(raw1)) //Generate a new token to guard against BREACH.
        } yield res.addCookie(Cookie(name = cookieName, content = newToken))
      }.mapF(f => OptionT.liftF(f.getOrElse(Response[F](Status.Forbidden))))

  def withNewToken: CSRFMiddleware[F] = _.andThen(r => OptionT.liftF(embedNew(r)))

  def embedNew(response: Response[F]): F[Response[F]] =
    generateToken.map(t => response.addCookie(Cookie(name = cookieName, content = t)))

}

object TSecCSRF {
  def apply[F[_]: Sync, A: MacTag: ByteEV](
      key: MacSigningKey[A],
      headerName: String = "X-TSec-Csrf",
      cookieName: String = "tsec-csrf",
      tokenLength: Int = 32,
      clock: Clock = Clock.systemUTC()
  )(implicit mac: JCAMacPure[F, A]): TSecCSRF[F, A] =
    new TSecCSRF[F, A](key, headerName, cookieName, tokenLength, clock)
}
