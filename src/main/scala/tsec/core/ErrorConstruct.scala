package tsec.core

import shapeless.{::, Generic, HNil}
import cats.syntax.either._

object ErrorConstruct {
  type ErrAux[A] = Generic[A] {
    type Repr = String :: HNil
  }

  def fromThrowable[A](e: Throwable)(implicit aux: ErrAux[A]): A = aux.from(e.getMessage :: HNil)

  class ErrConstructSyntax[B](val either: Either[Throwable, B]) extends AnyVal {
    def mapError[A: ErrAux] = either.leftMap[A](fromThrowable[A])
  }

  implicit def errSyntax[B](c: Either[Throwable, B]): ErrConstructSyntax[B] = new ErrConstructSyntax[B](c)

}
