package tsec.mac.core

trait MacAlgebra[F[_], A, K[_]] {
  type M

  def genInstance: F[M]

  def sign(content: Array[Byte], key: MacSigningKey[K[A]]): F[Array[Byte]]

}
