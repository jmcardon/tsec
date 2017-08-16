package tsec.core

private[tsec] abstract class ErrorConstruct[T](f: String => T) {
  def fromThrowable(e: Throwable): T = f(e.getMessage)
}
