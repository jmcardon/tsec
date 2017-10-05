package tsec.cipher.common

/** Base CipherError trait */
sealed trait CipherError extends Exception with Product with Serializable {
  def cause: String

  override def fillInStackTrace(): Throwable = this
}

/** Error thrown if the instance is invalid */
case class InstanceInitError(cause: String) extends CipherError

/** Error possibly thrown during encryption */
case class EncryptError(cause: String) extends CipherError

/** Error with incorrect iv len */
case class IvError(cause: String) extends CipherError

/**AAD error */
case class AADError(cause: String) extends CipherError

/**Error with incorrect key */
case class CipherKeyError(cause: String) extends CipherError

/** Error during decryption */
case class DecryptError(cause: String) extends CipherError

/** Error during key construction/generation */
case class CipherKeyBuildError(cause: String) extends CipherError

/** Ciphertext related errors */
case class CipherTextError(cause: String) extends CipherError

/** NoSuchInstance error*/
case object NoSuchInstanceError extends CipherError {
  def cause: String =
    "The combination for the cipher parameters given does not exist, or is not present in your JVM"
}
