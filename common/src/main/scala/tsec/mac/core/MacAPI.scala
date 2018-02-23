package tsec.mac.core

trait MacAPI[A, MK[_]] {

  def sign[F[_]](in: Array[Byte], key: MK[A])(implicit M: MessageAuth[F, A, MK]): F[MAC[A]] =
    M.sign(in, key)

  def verify[F[_]](in: Array[Byte], hashed: MAC[A], key: MK[A])(implicit M: MessageAuth[F, A, MK]): F[Boolean] =
    M.verify(in, hashed, key)

}
