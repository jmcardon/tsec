package fucc.all.encryption.messagedigests.core

import cats.Monoid

trait HashAlgebra[T] {
  type S
  implicit def monoid: Monoid[S]
  def liftS(s: Array[Byte]): S

  def hash(s: Array[Byte]): Array[Byte]

  def consume(state: S): Array[Byte]

}