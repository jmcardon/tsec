package tsec

import java.nio.charset.{Charset, StandardCharsets}
import cats.evidence.Is
import tsec.common._
import tsec.passwordhashers.core.PasswordHasher

package object passwordhashers {

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

  implicit class HasherSyntax(val password: String) extends AnyVal {

    @deprecated(
      """Password hashing this way is side effecting. Please use the methods
        |in the companion object of the particular hash algorithm,
        |`i.e` BCrypt.hashpw or BCrypt.hashpwUnsafe
      """.stripMargin,
      "0.0.1-M6"
    )
    def hashPassword[T](implicit passwordHasher: PasswordHasher[T]): PasswordHash[T] =
      passwordHasher.hashpwUnsafe(password)

    @deprecated(
      """Password hashing this way is side effecting. Please use the methods
        |in the companion object of the particular hash algorithm,
        |`i.e` BCrypt.checkpw or BCrypt.checkpwUnsafe
      """.stripMargin,
      "0.0.1-M6"
    )
    def checkWithHash[T](hash: PasswordHash[T])(implicit passwordHasher: PasswordHasher[T]): Boolean =
      passwordHasher.checkpwUnsafe(password, hash)
  }
}
