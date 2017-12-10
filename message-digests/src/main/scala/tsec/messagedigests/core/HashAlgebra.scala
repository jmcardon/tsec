package tsec.messagedigests.core

trait HashAlgebra[T] {
  type H

  def genInstance(): H

  def hash(s: Array[Byte]): Array[Byte]

}
