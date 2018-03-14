package tsec.mac.jca

import tsec.common.TSecError

sealed trait MacError extends TSecError

case class MacInstanceError(cause: String) extends MacError

case class MacInitError(cause: String) extends MacError

case class MacSigningError(cause: String) extends MacError

case class MacKeyBuildError(cause: String) extends MacError

case class MacVerificationError(cause: String) extends MacError
