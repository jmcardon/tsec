package tsec.cipher.asymmetric.core

import com.softwaremill.tagging.@@
import tsec.cipher.common.{CipherKeyError, KeyPair}


trait AsymmetricKeyGenerator[T, A, B] {
  def generateKeyPair(): Either[CipherKeyError, KeyPair[A, B] @@ T]
  def generateKeyPairUnsafe(): KeyPair[A, B] @@ T
}
