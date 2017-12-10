package tsec.passwordhashers

import java.nio.CharBuffer

import cats.effect.Sync
import tsec.passwordhashers.core._
import tsec.common.ByteUtils
import tsec.passwordhashers.imports.internal.JBCrypt
import tsec.common._

package object imports {

  /** https://security.stackexchange.com/questions/17207/recommended-of-rounds-for-bcrypt
    * Default is 10 on most applications
    */
  val DefaultBcryptRounds = 10

  /** https://crypto.stackexchange.com/questions/35423/appropriate-scrypt-parameters-when-generating-an-scrypt-hash */
  val DefaultSCryptN = 16384
  val DefaultSCryptR = 8
  val DefaultSCryptP = 1

  /** http://www.tarsnap.com/scrypt/scrypt-slides.pdf */
  val SCryptHardenedN = 262144
  val SCryptHardnedR  = 8
  val SCryptHardenedP = 2

  sealed trait BCrypt

  implicit object BCrypt extends PasswordHasher[BCrypt] {

    private[tsec] def hashPassUnsafe(p: Array[Byte]): String =
      JBCrypt.hashpw(p, JBCryptUtil.genSalt(DefaultBcryptRounds))

    private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[BCrypt]) =
      JBCrypt.checkpw(p, hash)

    def hashpwWithRounds[F[_]](p: String, rounds: Int)(implicit F: Sync[F]): F[PasswordHash[BCrypt]] =
      hashpwWithRounds[F](p.utf8Bytes, rounds)

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

  sealed trait SCrypt

  implicit object SCrypt extends PasswordHasher[SCrypt] {

    private[tsec] def hashPassUnsafe(p: Array[Byte]): String =
      SCryptUtil.scrypt(p, DefaultSCryptN, DefaultSCryptR, DefaultSCryptP)

    private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[SCrypt]) =
      SCryptUtil.check(p, hash)
  }

  sealed trait HardenedSCrypt

  implicit object HardenedSCrypt extends PasswordHasher[HardenedSCrypt] {
    private[tsec] def hashPassUnsafe(p: Array[Byte]) =
      SCryptUtil.scrypt(p, SCryptHardenedN, SCryptHardnedR, SCryptHardenedP)

    private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[HardenedSCrypt]) =
      SCryptUtil.check(p, hash)
  }
}
