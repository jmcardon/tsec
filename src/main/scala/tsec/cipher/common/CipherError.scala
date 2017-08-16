package tsec.cipher.common

sealed trait CipherError extends Product with Serializable {
  def message: String
}

/**
 * Error thrown if the instance is invalid
 */
case class InstanceInitError(message: String) extends CipherError

object InstanceInitError extends ErrorConstruct[InstanceInitError](new InstanceInitError(_))

/**
 * Error possibly thrown during encryption
 */
case class EncryptError(message: String) extends CipherError

object EncryptError extends ErrorConstruct[EncryptError](new EncryptError(_))

/**
 * Error with incorrect iv len
 */
case class IvError(message: String) extends CipherError

object IvError extends ErrorConstruct[IvError](new IvError(_))

/**
 * AAD error
 */
case class AADError(message: String) extends CipherError

object AADError extends ErrorConstruct[AADError](new AADError(_))

/**
 * Error with incorrect key
 */
case class KeyError(message: String) extends CipherError

object KeyError extends ErrorConstruct[KeyError](new KeyError(_))

/**
 * Error during decryption
 */
case class DecryptError(message: String) extends CipherError

object DecryptError extends ErrorConstruct[DecryptError](new DecryptError(_))


/**
  * Error during signing
  */
case class SignError(message: String) extends CipherError

object SignError extends ErrorConstruct[SignError](new SignError(_))


sealed private[common] abstract class ErrorConstruct[T](f: String => T) {
  def fromThrowable(e: Throwable): T = f(e.getMessage)
}
