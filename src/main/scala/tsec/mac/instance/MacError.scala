package tsec.mac.instance

sealed trait MacError extends Throwable with Product with Serializable{
  def cause: String

  override def fillInStackTrace(): Throwable = this
}
case class MacInstanceError(cause: String) extends MacError

case class MacInitError(cause: String) extends MacError

case class MacSigningError(cause: String) extends MacError

case class MacKeyBuildError(cause: String) extends MacError
