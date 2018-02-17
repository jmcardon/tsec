package tsec.authentication

import java.time.Instant

import cats.effect.IO
import tsec.cipher.symmetric.imports._

class EncryptedCookieAuthenticatorTests extends EncryptedCookieAuthenticatorSpec {

  AuthenticatorTest[AuthEncryptedCookie[AES128, Int]](
    "AES128 Authenticator w\\ backing store",
    genStatefulAuthenticator[AES128]
  )
  AuthenticatorTest[AuthEncryptedCookie[AES192, Int]](
    "AES192 Authenticator w\\ backing store",
    genStatefulAuthenticator[AES192]
  )
  AuthenticatorTest[AuthEncryptedCookie[AES256, Int]](
    "AES256 Authenticator w\\ backing store",
    genStatefulAuthenticator[AES256]
  )
  AuthenticatorTest[AuthEncryptedCookie[AES128, Int]](
    "AES128 Authenticator stateless",
    genStatelessAuthenticator[AES128]
  )
  AuthenticatorTest[AuthEncryptedCookie[AES192, Int]](
    "AES192 Authenticator stateless",
    genStatelessAuthenticator[AES192]
  )
  AuthenticatorTest[AuthEncryptedCookie[AES256, Int]](
    "AES256 Authenticator stateless",
    genStatelessAuthenticator[AES256]
  )

  requestAuthTests[AuthEncryptedCookie[AES128, Int]](
    "AES128 Authenticator w\\ backing store",
    genStatefulAuthenticator[AES128]
  )
  requestAuthTests[AuthEncryptedCookie[AES192, Int]](
    "AES192 Authenticator w\\ backing store",
    genStatefulAuthenticator[AES192]
  )
  requestAuthTests[AuthEncryptedCookie[AES256, Int]](
    "AES256 Authenticator w\\ backing store",
    genStatefulAuthenticator[AES256]
  )
  requestAuthTests[AuthEncryptedCookie[AES128, Int]](
    "AES128 Authenticator stateless",
    genStatelessAuthenticator[AES128]
  )
  requestAuthTests[AuthEncryptedCookie[AES192, Int]](
    "AES192 Authenticator stateless",
    genStatelessAuthenticator[AES192]
  )
  requestAuthTests[AuthEncryptedCookie[AES256, Int]](
    "AES256 Authenticator stateless",
    genStatelessAuthenticator[AES256]
  )

  def encryptedCookieAuthenticatorTests[A: AES](auth: AuthSpecTester[AuthEncryptedCookie[A, Int]], extra: String) = {
    behavior of s"$extra Encrypted cookie authenticator with AES${AES[A].keySizeBytes * 8}"

    it should "expire the cookie on discard" in {

      val program = for {
        cookie <- auth.auth.create(0)
        expire <- auth.auth.discard(cookie)
        now    <- IO(Instant.now())
      } yield EncryptedCookieAuthenticator.isExpired[Int, A](expire, now, None)

      program.unsafeRunSync() mustBe false
    }
  }

  encryptedCookieAuthenticatorTests[AES256](genStatelessAuthenticator[AES256], "Stateless")
  encryptedCookieAuthenticatorTests[AES256](genStatefulAuthenticator[AES256], "Stateful")

}
