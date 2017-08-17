package tsec.mac.instance

sealed trait MacError extends Product with Serializable{
  def cause: String
}
case class MacInstanceError(cause: String) extends MacError

case class MacInitError(cause: String) extends MacError

case class MacSigningError(cause: String) extends MacError

case class MacKeyBuildError(cause: String) extends MacError
