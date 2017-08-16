package tsec.core

import javax.crypto.KeyGenerator

/**
 * Our symmetric key generator, abstracted out
 * This is not so easy given keyError is useful to CipherError as well, but
 * duplicated classes is a nono
 *
 * @tparam A The algorithm to generate the key for
 * @tparam K the key type, i.e Symmetric cipher or Mac key
 */
trait JKeyGenerator[A, K[_]] {
  def keyLength: Int
  def generator: KeyGenerator
  def generateKey(): Either[KeyBuilderError, K[A]]
  def generateKeyUnsafe(): K[A]
  def buildKey(key: Array[Byte]): Either[KeyBuilderError, K[A]]
  def buildKeyUnsafe(key: Array[Byte]): K[A]
}
