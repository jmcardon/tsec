package tsec.core

import cats.MonadError

import scala.util.control.NonFatal

object CatsBackportUtils {
  implicit class MErrPort[F[_], E](val m: MonadError[F, E]) extends AnyVal {
    def adaptError[A](fa: F[A])(pf: PartialFunction[E, E]): F[A] =
      m.flatMap(m.attempt(fa))(_.fold(e => m.raiseError(pf.applyOrElse[E, E](e, _ => e)), m.pure))

    /**
      * Often E is Throwable. Here we try to call pure or catch
      * and raise.
      */
    def adaptNonFatal[A](a: => A)(f: E => E)(implicit ev: Throwable <:< E): F[A] =
      try m.pure(a)
      catch {
        case NonFatal(e) => m.raiseError(f(e))
      }
  }

}
