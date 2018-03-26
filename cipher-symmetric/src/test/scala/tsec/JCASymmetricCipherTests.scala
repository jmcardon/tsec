package tsec

import tsec.cipher.symmetric.jca._

class JCASymmetricCipherTests extends JCASymmetricSpec {

  authCipherTest(AES128GCM)
  cipherTest(AES128CBC)
  cipherTest(AES128CTR)

  authCipherTest(AES192GCM)
  cipherTest(AES192CBC)
  cipherTest(AES192CTR)

  authCipherTest(AES256GCM)
  cipherTest(AES256CBC)
  cipherTest(AES256CTR)

}
