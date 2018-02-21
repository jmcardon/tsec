package tsec.passwordhashers

import java.nio.charset.{Charset, StandardCharsets}
import tsec.common.TSecError

package object core {

  type PasswordHash[A] = PasswordHash.PHash[A]

  private[tsec] val defaultCharset: Charset = StandardCharsets.UTF_8

  object PasswordHash {
    type PHash[A] <: String

    def apply[A](pw: String): PasswordHash[A] = pw.asInstanceOf[PasswordHash[A]]
    def subst[A]: PartiallyApplied[A]         = new PartiallyApplied[A]

    private[core] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[String]): F[PasswordHash[A]] = value.asInstanceOf[F[PasswordHash[A]]]
    }
  }

  final case class PasswordError(cause: String) extends TSecError
}
