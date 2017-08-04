package fucc.all.encryption.messagedigests.core

import cats.Monoid

trait DigestAlgebra[F[_], T] {
  type S
  implicit def monoid: Monoid[S]
  def liftS(s: Array[Byte]): S

  def hash(s: Array[Byte]): F[Array[Byte]]

  def consume(state: S): F[Array[Byte]]

}