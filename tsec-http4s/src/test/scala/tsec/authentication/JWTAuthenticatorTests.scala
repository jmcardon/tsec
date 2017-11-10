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

  /** Stateful Bearer Auth **/
  AuthenticatorTest[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Stateful Bearer Authenticator",
    stateful[HMACSHA256]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Stateful Bearer Authenticator",
    stateful[HMACSHA384]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Stateful Bearer Authenticator",
    stateful[HMACSHA512]
  )
  requestAuthTests[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Stateful Bearer Authenticator",
    stateful[HMACSHA256]
  )
  requestAuthTests[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Stateful Bearer Authenticator",
    stateful[HMACSHA384]
  )
  requestAuthTests[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Stateful Bearer Authenticator",
    stateful[HMACSHA512]
  )

  /** End Stateful Bearer Auth **/
  /** Stateful Arbitrary Header Auth **/
  AuthenticatorTest[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Stateful Arbitrary Header Authenticator",
    statefulArbitraryH[HMACSHA256]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Stateful Arbitrary Header Authenticator",
    statefulArbitraryH[HMACSHA384]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Stateful Arbitrary Header Authenticator",
    statefulArbitraryH[HMACSHA512]
  )
  requestAuthTests[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Stateful Arbitrary Header Authenticator",
    statefulArbitraryH[HMACSHA256]
  )
  requestAuthTests[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Stateful Arbitrary Header Authenticator",
    statefulArbitraryH[HMACSHA384]
  )
  requestAuthTests[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Stateful Arbitrary Header Authenticator",
    statefulArbitraryH[HMACSHA512]
  )

  /** End Stateful Arbitrary Header Auth **/
  /** Basic Stateless tests **/
  AuthenticatorTest[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Stateless Authenticator",
    stateless[HMACSHA256]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Stateless Authenticator",
    stateless[HMACSHA384]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Stateless Authenticator",
    stateless[HMACSHA512]
  )

  requestAuthTests[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Stateless Authenticator",
    stateless[HMACSHA256]
  )
  requestAuthTests[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Stateless Authenticator",
    stateless[HMACSHA384]
  )
  requestAuthTests[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Stateless Authenticator",
    stateless[HMACSHA512]
  )

  /**End Basic Stateless tests **/
  /** Stateless Encrypted Arbitrary Header tests **/
  AuthenticatorTest[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Encrypted Stateless Authenticator",
    statelessEncrypted[HMACSHA256, AES128]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Encrypted Stateless Authenticator",
    statelessEncrypted[HMACSHA384, AES128]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Encrypted Stateless Authenticator",
    statelessEncrypted[HMACSHA512, AES128]
  )

  requestAuthTests[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Encrypted Stateless Authenticator",
    statelessEncrypted[HMACSHA256, AES128]
  )
  requestAuthTests[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Encrypted Stateless Authenticator",
    statelessEncrypted[HMACSHA384, AES128]
  )
  requestAuthTests[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Encrypted Stateless Authenticator",
    statelessEncrypted[HMACSHA512, AES128]
  )

  /** End Stateless Encrypted  Arbitrary Header Tests **/

  /** Stateless Encrypted Auth Bearer Header tests **/
  AuthenticatorTest[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Encrypted Bearer Token Stateless Authenticator",
    statelessBearerEncrypted[HMACSHA256, AES128]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Encrypted Bearer Token Stateless Authenticator",
    statelessBearerEncrypted[HMACSHA384, AES128]
  )
  AuthenticatorTest[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Encrypted Bearer Token Stateless Authenticator",
    statelessBearerEncrypted[HMACSHA512, AES128]
  )

  requestAuthTests[AugmentedJWT[HMACSHA256, Int]](
    "HMACSHA256 JWT Encrypted Bearer Token Stateless Authenticator",
    statelessBearerEncrypted[HMACSHA256, AES128]
  )
  requestAuthTests[AugmentedJWT[HMACSHA384, Int]](
    "HMACSHA384 JWT Encrypted Bearer Token Stateless Authenticator",
    statelessBearerEncrypted[HMACSHA384, AES128]
  )
  requestAuthTests[AugmentedJWT[HMACSHA512, Int]](
    "HMACSHA512 JWT Encrypted Bearer Token Stateless Authenticator",
    statelessBearerEncrypted[HMACSHA512, AES128]
  )
  /** End Stateless Encrypted Auth Bearer Header Tests **/


  def checkAuthHeader[A: ByteEV: JWTMacAlgo: MacTag](implicit cv: JWSMacCV[IO, A], macKeyGen: MacKeyGenerator[A]) = {
    behavior of MacTag[A].algorithm + " JWT Token64 check"
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
