package tsec.passwordhashers.instances

import com.lambdaworks.crypto.{SCryptUtil => JSCrypt}
import tsec.passwordhashers.core._

case class HardenedSCrypt(hashed: String)

object HardenedSCrypt {
  implicit lazy val HardenedSCryptPasswordHasher =
    new PasswordHasher[HardenedSCrypt] {
      def hashPw(pass: Password, opt: Rounds): HardenedSCrypt =
        HardenedSCrypt(
          SCryptUtil.scrypt(pass.pass, SCryptHardenedN, SCryptHardnedR, SCryptHardenedP)
        )

      def checkPassword(pass: Password, hashed: HardenedSCrypt): Boolean =
        SCryptUtil.check(pass.pass, hashed.hashed)
    }

  object Hardened extends ImplAlgebra[HardenedSCrypt]

  implicit object SCryptPasswordHasher
      extends PWHashPrograms[PasswordValidated, HardenedSCrypt](Hardened, Rounds(DefaultSCryptN))(
        HardenedSCryptPasswordHasher
      )
}
