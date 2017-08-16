package tsec.core

case class KeyBuilderError(message: String) extends AnyVal

object KeyBuilderError{
  def fromThrowable(e: Throwable) = KeyBuilderError(e.getMessage)
}
