package tsec

import tsec.cipher.symmetric.bouncy._

class BouncyCipherTests extends SymmetricSpec {

  authCipherTest[XSalsa20Poly1305, BouncySecretKey]("XSalsa20Poly1305Bouncy", XSalsa20Poly1305.defaultIvGen)
  aeadCipherTest[XChaCha20Poly1305, BouncySecretKey]("XChaCha20Poly1305Bouncy", XChaCha20Poly1305.defaultIvGen)

}
