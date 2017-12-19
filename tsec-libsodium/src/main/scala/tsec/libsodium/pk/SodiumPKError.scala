package tsec.libsodium.pk

import tsec.common.TSecError

trait SodiumPKError extends TSecError

case class SignatureError(cause: String) extends SodiumPKError
