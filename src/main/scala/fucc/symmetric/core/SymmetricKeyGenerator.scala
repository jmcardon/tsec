package fucc.symmetric.core

import fucc.cipher.core.SecretKey

trait SymmetricKeyGenerator[T] {
  def generateKey(): Either[KeyError, SecretKey[T]]
  def generateKeyUnsafe(): SecretKey[T]
  def buildKey(key: Array[Byte]): Either[KeyError, SecretKey[T]]
  def buildKeyUnsafe(key: Array[Byte]): SecretKey[T]
}



