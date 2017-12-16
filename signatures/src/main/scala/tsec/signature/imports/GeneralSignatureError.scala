package tsec.signature.imports

import tsec.common.TSecError

sealed trait SignatureError extends TSecError

case class GeneralSignatureError(cause: String) extends SignatureError

case class SignatureInitError(cause: String) extends SignatureError

case class SignatureVerificationError(cause: String) extends SignatureError

case class SignatureKeyError(cause: String) extends SignatureError
