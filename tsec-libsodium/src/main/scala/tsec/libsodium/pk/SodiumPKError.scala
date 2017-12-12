package tsec.libsodium.pk

trait SodiumPKError extends Exception {
  def c: String

  override def getMessage: String = c

  override def fillInStackTrace(): Throwable = this
}

case class SignatureError(c: String) extends SodiumPKError
