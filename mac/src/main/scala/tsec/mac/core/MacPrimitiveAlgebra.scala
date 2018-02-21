package tsec.mac.core

trait MacPrimitiveAlgebra[F[_], A, K[_]] {
  type M

  def genInstance: F[M]

  def sign(content: Array[Byte], key: K[A]): F[Array[Byte]]

}
