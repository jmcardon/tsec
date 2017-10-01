package tsec.signature.instance

case class SignatureError(message: String) extends Exception{
  override def getCause: Throwable = this

  override def getMessage: String = message

  override def fillInStackTrace(): Throwable = this
}
