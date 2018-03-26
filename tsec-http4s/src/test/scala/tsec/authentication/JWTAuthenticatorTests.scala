package tsec.authentication

import cats.effect.IO
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials}
import org.scalatest.prop.PropertyChecks
import tsec.cipher.symmetric.jca._
import tsec.jws.mac.{JWSMacCV, JWTMac}
import tsec.jwt.JWTClaims
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.keygen.symmetric.IdKeyGen
import tsec.mac.jca.{JCAMacTag, _}

class JWTAuthenticatorTests extends JWTAuthenticatorSpec with PropertyChecks {

  case class JWTTestingGroup[A, B](authenticator: A, embedder: B, title: String)

  /** backed **/
  def runStatefulAuthenticators[A: JWTMacAlgo](
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: IdKeyGen[A, MacSigningKey],
      M: JCAMacTag[A]
  ) =
    List[JWTTestingGroup[BackedAuth[A], Embedder[A]]](
      JWTTestingGroup(
        JWTAuthenticator.backed.inBearerToken[IO, Int, DummyUser, A](
          generalSettings.expiryDuration,
          generalSettings.maxIdle,
          _,
          _,
          _
        ),
        embedInBearerToken[Int, A],
        s"${M.algorithm} in bearer token no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.backed.inCookie[IO, Int, DummyUser, A](
          generalCookieSettings,
          _,
          _,
          _
        ),
        embedInCookie[Int, A](generalCookieSettings),
        s"${M.algorithm} in cookie no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.backed.inHeader[IO, Int, DummyUser, A](
          generalSettings,
          _,
          _,
          _
        ),
        embedInHeader[Int, A](generalSettings.headerName),
        s"${M.algorithm} in header no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.backed.inBearerToken[IO, Int, DummyUser, A](
          generalNoRollSettings.expiryDuration,
          generalNoRollSettings.maxIdle,
          _,
          _,
          _
        ),
        embedInBearerToken[Int, A],
        s"${M.algorithm} in bearer token rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.backed.inCookie[IO, Int, DummyUser, A](
          generalNoRollCookieSettings,
          _,
          _,
          _
        ),
        embedInCookie[Int, A](generalCookieSettings),
        s"${M.algorithm} in cookie rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.backed.inHeader[IO, Int, DummyUser, A](
          generalNoRollSettings,
          _,
          _,
          _
        ),
        embedInHeader[Int, A](generalSettings.headerName),
        s"${M.algorithm} in header rolling"
      ),
    ).foreach {
      case t =>
        AuthenticatorTest[AugmentedJWT[A, Int]](s"Authenticator Stateful spec: ${t.title}", stateful[A](t.authenticator, t.embedder))
        requestAuthTests[AugmentedJWT[A, Int]](s"Request Auth Stateful spec: ${t.title}", stateful[A](t.authenticator, t.embedder))
    }

  /** backed **/
  def runPartialStatelessAuthenticators[A: JWTMacAlgo](
    implicit cv: JWSMacCV[IO, A],
    macKeyGen: IdKeyGen[A, MacSigningKey],
    M: JCAMacTag[A]
  ) =
    List[JWTTestingGroup[UnBackedAuth[A], Embedder[A]]](
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inBearerToken[IO, Int, DummyUser, A](
          generalSettings.expiryDuration,
          generalSettings.maxIdle,
          _,
          _
        ),
        embedInBearerToken[Int, A],
        s"${M.algorithm} in bearer token no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inCookie[IO, Int, DummyUser, A](
          generalCookieSettings,
          _,
          _
        ),
        embedInCookie[Int, A](generalCookieSettings),
        s"${M.algorithm} in cookie no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inHeader[IO, Int, DummyUser, A](
          generalSettings,
          _,
          _
        ),
        embedInHeader[Int, A](generalSettings.headerName),
        s"${M.algorithm} in header no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inBearerToken[IO, Int, DummyUser, A](
          generalNoRollSettings.expiryDuration,
          generalNoRollSettings.maxIdle,
          _,
          _
        ),
        embedInBearerToken[Int, A],
        s"${M.algorithm} in bearer token rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inCookie[IO, Int, DummyUser, A](
          generalNoRollCookieSettings,
          _,
          _
        ),
        embedInCookie[Int, A](generalCookieSettings),
        s"${M.algorithm} in cookie rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inHeader[IO, Int, DummyUser, A](
          generalNoRollSettings,
          _,
          _
        ),
        embedInHeader[Int, A](generalSettings.headerName),
        s"${M.algorithm} in header rolling"
      ),
    ).foreach {
      case t =>
        AuthenticatorTest[AugmentedJWT[A, Int]](s"Authenticator Partial Stateless spec: ${t.title}", partialStateless[A](t.authenticator, t.embedder))
        requestAuthTests[AugmentedJWT[A, Int]](s"Request Auth Partial Stateless spec: ${t.title}", partialStateless[A](t.authenticator, t.embedder))
    }


  runStatefulAuthenticators[HMACSHA256]
  runStatefulAuthenticators[HMACSHA384]
  runStatefulAuthenticators[HMACSHA512]

  runPartialStatelessAuthenticators[HMACSHA256]
  runPartialStatelessAuthenticators[HMACSHA384]
  runPartialStatelessAuthenticators[HMACSHA512]


  /** End Stateless Encrypted Auth Bearer Header Tests **/
  def checkAuthHeader[A: JWTMacAlgo: JCAMacTag](implicit cv: JWSMacCV[IO, A], macKeyGen: MacKeyGen[IO, A]) = {
    behavior of JCAMacTag[A].algorithm + " JWT Token64 check"
    macKeyGen.generateKey
      .map { key =>
        it should "pass token68 check" in {
          forAll { (testSubject: String) =>
            val token = "Bearer "

            val (rawToken, parsed) = JWTMac
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
