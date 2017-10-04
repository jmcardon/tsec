package tsec.cipher.asymmetric.core

import java.security.KeyPairGenerator

trait JKeyPairGenerator[A, K[_], KE] {
  def keyLength: Int

  def generator: KeyPairGenerator

  def generateKeyPair(): Either[KE, K[A]]

  def generateKeyPairUnsafe(): K[A]
}
