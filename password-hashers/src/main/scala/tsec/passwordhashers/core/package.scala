package tsec.passwordhashers

package object core {

  final case class PasswordError(reason: String) extends Exception {
    override def getMessage: String = reason

    override def fillInStackTrace(): Throwable = this
  }
}
