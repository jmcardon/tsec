package tsec.cipher.common

import shapeless._

sealed trait CipherError extends Throwable with Product with Serializable {
  def cause: String
}

/**
  * Error thrown if the instance is invalid
  */
case class InstanceInitError(cause: String) extends CipherError

/**
  * Error possibly thrown during encryption
  */
case class EncryptError(cause: String) extends CipherError

/**
  * Error with incorrect iv len
  */
case class IvError(cause: String) extends CipherError

/**
  * AAD error
  */
case class AADError(cause: String) extends CipherError

/**
  * Error with incorrect key
  */
case class CipherKeyError(cause: String) extends CipherError

/**
  * Error during decryption
  */
case class DecryptError(cause: String) extends CipherError

/**
 * Error during key construction/generation
 */
case class CipherKeyBuildError(cause: String) extends CipherError

case object NoSuchInstanceError extends CipherError {
  def cause: String = "The combination for the cipher parameters given does not exist"
}
