package tsec

import tsec.cipher.common.mode._
import tsec.cipher.common.padding._
import tsec.cipher.symmetric.instances._

class JCASymmetricCipherTests extends SymmetricSpec {

  authCipherTest[AES128, GCM, NoPadding]
  cipherTest[AES128, CBC, PKCS7Padding]
  cipherTest[AES128, CTR, PKCS7Padding]
  cipherTest[AES128, CTR, NoPadding]

  authCipherTest[AES192, GCM, NoPadding]
  cipherTest[AES192, CBC, PKCS7Padding]
  cipherTest[AES192, CTR, PKCS7Padding]
  cipherTest[AES192, CTR, NoPadding]

  authCipherTest[AES256, GCM, NoPadding]
  cipherTest[AES256, CBC, PKCS7Padding]
  cipherTest[AES256, CTR, PKCS7Padding]
  cipherTest[AES256, CTR, NoPadding]

}
