package tsec.cipher.symmetric.libsodium

import tsec.common.TSecError

trait SodiumCipherError extends TSecError

object SodiumCipherError {

  case class EncryptError private[tsec] (cause: String) extends SodiumCipherError

  case class StreamEncryptError private[tsec] (cause: String) extends SodiumCipherError

  case class DecryptError private[tsec] (cause: String) extends SodiumCipherError

  case class StreamDecryptError private[tsec] (cause: String) extends SodiumCipherError

  case class CipherKeyError private[tsec] (cause: String) extends SodiumCipherError

}
