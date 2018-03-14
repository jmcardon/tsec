package tsec.passwordhashers.jca

import java.nio.CharBuffer

import cats.effect.Sync
import tsec.common._
import tsec.passwordhashers._
import tsec.passwordhashers.jca.internal.JBCrypt

sealed trait BCrypt

object BCrypt extends JCAPasswordPlatform[BCrypt] {

  private[tsec] def unsafeHashpw(p: Array[Byte]): String =
    JBCrypt.hashpw(p, JBCryptUtil.genSalt(DefaultBcryptRounds))

  private[tsec] def unsafeCheckpw(p: Array[Byte], hash: PasswordHash[BCrypt]): Boolean =
    JBCrypt.checkpw(p, hash)

  def hashpwWithRounds[F[_]](p: String, rounds: Int)(implicit F: Sync[F]): F[PasswordHash[BCrypt]] =
    hashpwWithRounds[F](p.asciiBytes, rounds)

  def hashpwWithRounds[F[_]](p: Array[Byte], rounds: Int)(implicit F: Sync[F]): F[PasswordHash[BCrypt]] =
    if (rounds < 10 || rounds > 30)
      F.raiseError(PasswordError("Invalid number of rounds"))
    else
      F.delay {
        val out = PasswordHash[BCrypt](JBCrypt.hashpw(p, JBCryptUtil.genSalt(rounds)))
        ByteUtils.zeroByteArray(p)
        out
      }

  def hashpwWithRounds[F[_]](p: Array[Char], rounds: Int)(implicit F: Sync[F]): F[PasswordHash[BCrypt]] =
    if (rounds < 10 || rounds > 30)
      F.raiseError(PasswordError("Invalid number of rounds"))
    else
      F.delay {
        val charbuffer = CharBuffer.wrap(p)
        val bytes      = defaultCharset.encode(charbuffer).array()
        val out        = PasswordHash[BCrypt](JBCrypt.hashpw(bytes, JBCryptUtil.genSalt(rounds)))
        //Clear pass
        ByteUtils.zeroCharArray(p)
        ByteUtils.zeroByteArray(bytes)
        out
      }
}
