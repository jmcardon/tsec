package tsec.cipher.core

sealed trait CipherError extends Product with Serializable {
  def message: String
}

case class InstanceInitError(message: String) extends CipherError
case class EncryptError(message: String) extends CipherError
case class IvError(message: String) extends CipherError
case class AADError(message: String) extends CipherError
case class KeyError(message: String) extends CipherError
case class DecryptError(message: String) extends CipherError
