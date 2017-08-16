package tsec.mac

import tsec.core.ErrorConstruct

package object instance {

  sealed trait MacError extends Product with Serializable{
    def cause: String
  }
  case class MacInstanceError(cause: String) extends MacError

  object MacInstanceError extends ErrorConstruct[MacInstanceError](new MacInstanceError(_))

  case class MacInitError(cause: String) extends MacError

  object MacInitError extends ErrorConstruct[MacInitError](new MacInitError(_))

  case class MacSigningError(cause: String) extends MacError

  object MacSigningError extends ErrorConstruct[MacSigningError](new MacSigningError(_))

}
