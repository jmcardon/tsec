package tsec.core

import javax.crypto.KeyGenerator

/**
 * Our symmetric key generator, abstracted out
 * TODO: KeyError to common package
 * This is not so easy given keyError is useful to CipherError as well, but
 * duplicated classes is a nono
 *
 * @tparam T
 * @tparam K
 */
trait JKeyGenerator[T, K[_]] {
  def keyLength: Int
  def generator: KeyGenerator
  def generateKey(): Either[KeyBuilderError, K[T]]
  def generateKeyUnsafe(): K[T]
  def buildKey(key: Array[Byte]): Either[KeyBuilderError, K[T]]
  def buildKeyUnsafe(key: Array[Byte]): K[T]
}
