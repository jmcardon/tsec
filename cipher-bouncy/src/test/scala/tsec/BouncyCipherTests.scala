package tsec

import tsec.cipher.symmetric.bouncy._

class BouncyCipherTests extends SymmetricSpec {

  authCipherTest[XSalsa20Poly1305, BouncySecretKey]("XSalsa20Poly1305Bouncy", XSalsa20Poly1305.defaultIvGen)
  aeadCipherTest[XChaCha20Poly1305, BouncySecretKey]("XChaCha20Poly1305Bouncy", XChaCha20Poly1305.defaultIvGen)
  aeadCipherTest[ChaCha20Poly1305, BouncySecretKey]("ChaCha20Poly1305Bouncy", ChaCha20Poly1305.defaultIvGen)
  aeadCipherTest[ChaCha20Poly1305IETF, BouncySecretKey]("ChaCha20Poly1305IETFBouncy", ChaCha20Poly1305IETF.defaultIvGen)

}
