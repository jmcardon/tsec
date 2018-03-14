package tsec.cipher.asymmetric.libsodium

import tsec.common.TSecError

trait SodiumPKError extends TSecError

case class SodiumSignatureError(cause: String) extends SodiumPKError
