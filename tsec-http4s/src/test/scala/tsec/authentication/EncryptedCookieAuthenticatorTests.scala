package tsec.authentication

import java.time.Instant

import cats.effect.IO
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._

class EncryptedCookieAuthenticatorTests extends EncryptedCookieAuthenticatorSpec {

  AuthenticatorTest[AuthEncryptedCookie[AES128GCM, Int]](
    "AES128GCM Authenticator w\\ backing store",
    genStatefulAuthenticator[AES128GCM]
  )
  AuthenticatorTest[AuthEncryptedCookie[AES192GCM, Int]](
    "AES192GCM Authenticator w\\ backing store",
    genStatefulAuthenticator[AES192GCM]
  )
  AuthenticatorTest[AuthEncryptedCookie[AES256GCM, Int]](
    "AES256GCM Authenticator w\\ backing store",
    genStatefulAuthenticator[AES256GCM]
  )
  AuthenticatorTest[AuthEncryptedCookie[AES128GCM, Int]](
    "AES128GCM Authenticator stateless",
    genStatelessAuthenticator[AES128GCM]
  )
  AuthenticatorTest[AuthEncryptedCookie[AES192GCM, Int]](
    "AES192GCM Authenticator stateless",
    genStatelessAuthenticator[AES192GCM]
  )
  AuthenticatorTest[AuthEncryptedCookie[AES256GCM, Int]](
    "AES256GCM Authenticator stateless",
    genStatelessAuthenticator[AES256GCM]
  )

  requestAuthTests[AuthEncryptedCookie[AES128GCM, Int]](
    "AES128GCM Authenticator w\\ backing store",
    genStatefulAuthenticator[AES128GCM]
  )
  requestAuthTests[AuthEncryptedCookie[AES192GCM, Int]](
    "AES192GCM Authenticator w\\ backing store",
    genStatefulAuthenticator[AES192GCM]
  )
  requestAuthTests[AuthEncryptedCookie[AES256GCM, Int]](
    "AES256GCM Authenticator w\\ backing store",
    genStatefulAuthenticator[AES256GCM]
  )
  requestAuthTests[AuthEncryptedCookie[AES128GCM, Int]](
    "AES128GCM Authenticator stateless",
    genStatelessAuthenticator[AES128GCM]
  )
  requestAuthTests[AuthEncryptedCookie[AES192GCM, Int]](
    "AES192GCM Authenticator stateless",
    genStatelessAuthenticator[AES192GCM]
  )
  requestAuthTests[AuthEncryptedCookie[AES256GCM, Int]](
    "AES256GCM Authenticator stateless",
    genStatelessAuthenticator[AES256GCM]
  )

  def encryptedCookieAuthenticatorTests[A: AESGCM](
      auth: AuthSpecTester[AuthEncryptedCookie[A, Int]],
      extra: String
  ): Unit = {
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

  encryptedCookieAuthenticatorTests[AES256GCM](genStatelessAuthenticator[AES256GCM], "Stateless")
  encryptedCookieAuthenticatorTests[AES256GCM](genStatefulAuthenticator[AES256GCM], "Stateful")

}
