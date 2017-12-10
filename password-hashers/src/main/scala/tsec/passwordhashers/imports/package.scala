package tsec.passwordhashers

import java.nio.charset.{Charset, StandardCharsets}

import cats.evidence.Is
import tsec.passwordhashers.core._
import com.lambdaworks.crypto.{SCryptUtil => JSCrypt}

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

  }

  sealed trait SCrypt

  implicit object SCrypt extends PasswordHasher[SCrypt] {

    private[tsec] def hashPassUnsafe(p: Array[Byte]): String =
      SCryptUtil.scrypt(p, DefaultSCryptN.toInt, DefaultSCryptR, DefaultSCryptP)

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
