package tsec.cipher.common

import tsec.common.TSecError

trait CipherErrors {

  /** Base CipherError trait */
  sealed trait CipherError extends TSecError

  /** Error thrown if the instance is invalid */
  case class InstanceInitError(cause: String) extends CipherError

  /** Error possibly thrown during encryption */
  case class EncryptError(cause: String) extends CipherError

  /** Error with incorrect iv len */
  case class IvError(cause: String) extends CipherError

  /** AAD error */
  case class AADError(cause: String) extends CipherError

  /** Error with incorrect key */
  case class CipherKeyError(cause: String) extends CipherError

  /** Error during decryption */
  case class DecryptError(cause: String) extends CipherError

  /** Error during key construction/generation */
  case class CipherKeyBuildError(cause: String) extends CipherError

  /** Ciphertext related errors */
  case class CipherTextError(cause: String) extends CipherError

  /** Authentication tag related errors */
  case class AuthTagError(cause: String) extends CipherError

  /** NoSuchInstance error */
  case object NoSuchInstanceError extends CipherError {
    def cause: String =
      "The combination for the cipher parameters given does not exist, or is not present in your JVM"
  }

  type NoSuchInstanceError = NoSuchInstanceError.type

}
