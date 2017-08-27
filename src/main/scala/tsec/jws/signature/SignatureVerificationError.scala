package tsec.jws.signature

case class SignatureVerificationError(message: String) extends Throwable {
  override def fillInStackTrace(): Throwable = this
}
