package tsec.signature.imports

sealed trait SignatureError extends Exception with Product with Serializable

case class GeneralSignatureError(message: String) extends SignatureError {
  override def getCause: Throwable = this

  override def getMessage: String = message

  override def fillInStackTrace(): Throwable = this
}

case class SignatureInitError(message: String) extends SignatureError {
  override def getCause: Throwable = this

  override def getMessage: String = message

  override def fillInStackTrace(): Throwable = this
}

case class SignatureVerificationError(message: String) extends SignatureError {
  override def getCause: Throwable = this

  override def getMessage: String = message

  override def fillInStackTrace(): Throwable = this
}

case class SignatureKeyError(message: String) extends SignatureError {
  override def getCause: Throwable = this

  override def getMessage: String = message

  override def fillInStackTrace(): Throwable = this
}
