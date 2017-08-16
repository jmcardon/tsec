package tsec.cipher.common

import tsec.core.ErrorConstruct

sealed trait CipherError extends Product with Serializable {
  def cause: String
}

/**
 * Error thrown if the instance is invalid
 */
case class InstanceInitError(cause: String) extends CipherError

object InstanceInitError extends ErrorConstruct[InstanceInitError](new InstanceInitError(_))

/**
 * Error possibly thrown during encryption
 */
case class EncryptError(cause: String) extends CipherError

object EncryptError extends ErrorConstruct[EncryptError](new EncryptError(_))

/**
 * Error with incorrect iv len
 */
case class IvError(cause: String) extends CipherError

object IvError extends ErrorConstruct[IvError](new IvError(_))

/**
 * AAD error
 */
case class AADError(cause: String) extends CipherError

object AADError extends ErrorConstruct[AADError](new AADError(_))

/**
 * Error with incorrect key
 */
case class CipherKeyError(cause: String) extends CipherError

object CipherKeyError extends ErrorConstruct[CipherKeyError](new CipherKeyError(_))

/**
 * Error during decryption
 */
case class DecryptError(cause: String) extends CipherError

object DecryptError extends ErrorConstruct[DecryptError](new DecryptError(_))


