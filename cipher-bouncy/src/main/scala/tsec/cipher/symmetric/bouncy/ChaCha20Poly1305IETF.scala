package tsec.cipher.symmetric.bouncy

import tsec.cipher.symmetric.bouncy.internal.ChaCha20IETFEngine

sealed trait ChaCha20Poly1305IETF

object ChaCha20Poly1305IETF extends IETFChaCha20Cipher[ChaCha20Poly1305IETF, ChaCha20IETFEngine] {

  val nonceSize: Int = 12

  protected def getCipherImpl: ChaCha20IETFEngine = new ChaCha20IETFEngine()
}
