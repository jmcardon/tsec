package tsec.jws.signature

case class SigVerificationError(message: String) extends Exception {
  override def fillInStackTrace(): Throwable = this
}
