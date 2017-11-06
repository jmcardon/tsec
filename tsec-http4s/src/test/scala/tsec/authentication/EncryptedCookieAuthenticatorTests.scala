package tsec.authentication

import tsec.cipher.symmetric.imports._

class EncryptedCookieAuthenticatorTests extends EncryptedCookieAuthenticatorSpec {

  AuthenticatorTest[AuthEncryptedCookie[AES128, Int]]("AES128 Authenticator w\\ backing store", genStatefulAuthenticator[AES128])
  AuthenticatorTest[AuthEncryptedCookie[AES192, Int]]("AES192 Authenticator w\\ backing store", genStatefulAuthenticator[AES192])
  AuthenticatorTest[AuthEncryptedCookie[AES256, Int]]("AES256 Authenticator w\\ backing store", genStatefulAuthenticator[AES256])
  AuthenticatorTest[AuthEncryptedCookie[AES128, Int]]("AES128 Authenticator stateless", genStatelessAuthenticator[AES128])
  AuthenticatorTest[AuthEncryptedCookie[AES192, Int]]("AES192 Authenticator stateless", genStatelessAuthenticator[AES192])
  AuthenticatorTest[AuthEncryptedCookie[AES256, Int]]("AES256 Authenticator stateless", genStatelessAuthenticator[AES256])

  requestAuthTests[AuthEncryptedCookie[AES128, Int]]("AES128 Authenticator w\\ backing store", genStatefulAuthenticator[AES128])
  requestAuthTests[AuthEncryptedCookie[AES192, Int]]("AES192 Authenticator w\\ backing store", genStatefulAuthenticator[AES192])
  requestAuthTests[AuthEncryptedCookie[AES256, Int]]("AES256 Authenticator w\\ backing store", genStatefulAuthenticator[AES256])
  requestAuthTests[AuthEncryptedCookie[AES128, Int]]("AES128 Authenticator stateless", genStatelessAuthenticator[AES128])
  requestAuthTests[AuthEncryptedCookie[AES192, Int]]("AES192 Authenticator stateless", genStatelessAuthenticator[AES192])
  requestAuthTests[AuthEncryptedCookie[AES256, Int]]("AES256 Authenticator stateless", genStatelessAuthenticator[AES256])
}
