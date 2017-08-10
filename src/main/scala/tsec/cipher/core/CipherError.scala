package tsec.cipher.core

sealed trait CipherError

case class EncryptError(message: String) extends CipherError
case class KeyError(message: String) extends CipherError
case class DecryptError(message: String) extends CipherError
