package tsec.authentication

import cats.effect.IO
import org.http4s.{AuthScheme, Credentials}
import org.http4s.headers.Authorization
import org.scalatest.prop.PropertyChecks
import tsec.cipher.symmetric.imports._
import tsec.common.ByteEV
import tsec.jws.mac.{JWSMacCV, JWTMac, JWTMacM}
import tsec.jwt.JWTClaims
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.mac.imports._

class JWTAuthenticatorTests extends JWTAuthenticatorSpec with PropertyChecks {

  AuthenticatorTest[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Stateful Authenticator",
    genStatefulAuthenticator[HMACSHA256]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Stateful Authenticator",
    genStatefulAuthenticator[HMACSHA384]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Stateful Authenticator",
    genStatefulAuthenticator[HMACSHA512]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Stateless Authenticator",
    genStateless[HMACSHA256, AES128]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Stateless Authenticator",
    genStateless[HMACSHA384, AES128]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Stateless Authenticator",
    genStateless[HMACSHA512, AES128]
  )

  requestAuthTests[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Stateful Authenticator",
    genStatefulAuthenticator[HMACSHA256]
  )
  requestAuthTests[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Stateful Authenticator",
    genStatefulAuthenticator[HMACSHA384]
  )
  requestAuthTests[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Stateful Authenticator",
    genStatefulAuthenticator[HMACSHA512]
  )
  requestAuthTests[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Stateless Authenticator",
    genStateless[HMACSHA256, AES128]
  )
  requestAuthTests[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Stateless Authenticator",
    genStateless[HMACSHA384, AES128]
  )
  requestAuthTests[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Stateless Authenticator",
    genStateless[HMACSHA512, AES128]
  )

  def checkAuthHeader[A: ByteEV: JWTMacAlgo: MacTag](implicit cv: JWSMacCV[IO, A], macKeyGen: MacKeyGenerator[A]) = {
    behavior of MacTag[A] + " JWT Token64 check"
    macKeyGen
      .generateLift[IO]
      .map { key =>
        it should "pass token68 check" in {
          forAll { (testSubject: String) =>
            val token = "Bearer "

            val (rawToken, parsed) = JWTMacM
              .buildToString(JWTClaims(subject = Some(testSubject)), key)
              .map(s => (s, Authorization.parse(token + s)))
              .unsafeRunSync()

            parsed mustBe Right(Authorization(Credentials.Token(AuthScheme.Bearer, rawToken)))
          }

        }
      }
      .unsafeRunSync()
  }

  checkAuthHeader[HMACSHA256]
  checkAuthHeader[HMACSHA384]
  checkAuthHeader[HMACSHA512]

}
