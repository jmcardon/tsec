package fucc.passwordhashers.instances

import com.lambdaworks.crypto.{SCryptUtil => JSCrypt}
import fucc.passwordhashers.core._

case class HardenedSCrypt(hashed: String)

object HardenedSCrypt {
  implicit lazy val HardenedSCryptPasswordHasher =
    new PasswordHasher[HardenedSCrypt] {
      def hashPw(pass: Password, opt: PasswordOpt): HardenedSCrypt =
        HardenedSCrypt(JSCrypt
          .scrypt(pass.pass, SCryptHardenedN, SCryptHardnedR, SCryptHardenedP))

      def checkPassword(pass: Password, hashed: HardenedSCrypt): Boolean =
        JSCrypt.check(pass.pass, hashed.hashed)
    }

  object Hardened extends ImplAlgebra[HardenedSCrypt]

  implicit object SCryptPasswordHasher
      extends PWHashPrograms[PasswordValidated, HardenedSCrypt](
        Hardened,
        Right(Rounds(DefaultSCryptN)))(HardenedSCryptPasswordHasher)
}
