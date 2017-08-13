package tsec.asymmetric.core

import com.softwaremill.tagging.@@
import tsec.cipher.core._


trait AsymmetricKeyGenerator[T, A, B] {
  def generateKeyPair(): Either[KeyError, KeyPair[A, B] @@ T]
  def generateKeyPairUnsafe(): KeyPair[A, B] @@ T
}
