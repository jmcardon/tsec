package tsec.passwordhashers

import java.nio.charset.{Charset, StandardCharsets}

import cats.evidence.Is
import tsec.common._

package object core {

  private[tsec] val defaultCharset: Charset = StandardCharsets.UTF_8

  private[tsec] val PasswordHash$$ : HKStringNewt = new HKStringNewt {
    type Repr[A] = String

    def is[A] = Is.refl[String]
  }

  type PasswordHash[A] = PasswordHash$$.Repr[A]

  object PasswordHash {
    def apply[A](pw: String): PasswordHash[A]      = is[A].coerce(pw)
    @inline def is[A]: Is[String, PasswordHash[A]] = PasswordHash$$.is[A]
  }

  final case class PasswordError(reason: String) extends Exception {
    override def getMessage: String = reason

    override def fillInStackTrace(): Throwable = this
  }
}
