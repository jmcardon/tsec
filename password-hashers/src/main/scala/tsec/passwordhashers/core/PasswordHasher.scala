package tsec.passwordhashers.core

import java.nio.CharBuffer
import java.util.{Arrays => JArr}
import cats.effect.Sync
import tsec.common._

trait PasswordHasher[A] {

  def hashPassword[F[_]](p: String)(implicit F: Sync[F]): F[PasswordHash[A]] = hashPassword[F](p.utf8Bytes)

  def hashPassword[F[_]](p: Array[Char])(implicit F: Sync[F]): F[PasswordHash[A]] = F.delay {
    val charbuffer = CharBuffer.wrap(p)
    val bytes      = defaultCharset.encode(charbuffer).array()
    val out        = hashPassUnsafe(bytes)
    //Clear pass
    ByteUtils.zeroCharArray(p)
    ByteUtils.zeroByteArray(bytes)
    PasswordHash[A](out)
  }

  def hashPassword[F[_]](p: Array[Byte])(implicit F: Sync[F]): F[PasswordHash[A]] = F.delay {
    val out = PasswordHash[A](hashPassUnsafe(p))
    ByteUtils.zeroByteArray(p)
    out
  }

  def check[F[_]: Sync](p: String, hash: PasswordHash[A]): F[Boolean] =
    check[F](p.utf8Bytes, hash)

  def check[F[_]](p: Array[Char], hash: PasswordHash[A])(implicit F: Sync[F]): F[Boolean] = F.delay {
    val charbuffer = CharBuffer.wrap(p)
    val bytes      = defaultCharset.encode(charbuffer).array()
    val out        = checkPassUnsafe(bytes, hash)
    //Clear pass
    ByteUtils.zeroCharArray(p)
    ByteUtils.zeroByteArray(bytes)
    out
  }

  def check[F[_]](p: Array[Byte], hash: PasswordHash[A])(implicit F: Sync[F]): F[Boolean] = F.delay {
    val out = checkPassUnsafe(p, hash)
    //Clear pass
    ByteUtils.zeroByteArray(p)
    out
  }

  private[tsec] def hashPassUnsafe(p: Array[Byte]): String

  private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[A]): Boolean
}
