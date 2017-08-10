package tsec.asymmetric.cipher.core

import tsec.symmetric.core.KeyError

trait AsymmetricKeyGenerator[T] {
  def generateKeyPair(): Either[KeyError, KeyPair[T]]
  def generateKeyPairUnsafe(): KeyPair[T]
}
