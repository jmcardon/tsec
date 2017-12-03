package tsec.libsodium.cipher

trait SodiumCipherError extends Exception {
  val c: String

  override def getMessage: String = c

  override def fillInStackTrace(): Throwable = this
}
object SodiumCipherError {

  case class EncryptError private[tsec](c: String) extends SodiumCipherError

  case class StreamEncryptError private[tsec](c: String) extends SodiumCipherError

  case class DecryptError private[tsec](c: String) extends SodiumCipherError

  case class StreamDecryptError private[tsec](c: String) extends SodiumCipherError

  case class CipherKeyError private[tsec](c: String) extends SodiumCipherError

}
