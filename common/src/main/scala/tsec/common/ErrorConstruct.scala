package tsec.common

import cats.syntax.either._

object ErrorConstruct {

  class ErrConstructSyntax[B](val either: Either[Throwable, B]) extends AnyVal {
    def mapError[A](f: String => A) = either.leftMap[A](e => f(e.getMessage))
  }

  implicit def errSyntax[B](c: Either[Throwable, B]): ErrConstructSyntax[B] = new ErrConstructSyntax[B](c)

}
