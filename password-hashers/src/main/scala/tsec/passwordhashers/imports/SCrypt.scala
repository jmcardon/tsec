package tsec.passwordhashers.imports

import com.lambdaworks.crypto.{SCryptUtil => JSCrypt}
import tsec.passwordhashers.core._

case class SCrypt(hashed: String)

object SCrypt {
  implicit lazy val ScryptPasswordHasher: PasswordHasher[SCrypt] =
    new PasswordHasher[SCrypt] {

      protected val defaultRounds: Rounds = Rounds(DefaultSCryptR)

      def hashPw(pass: Password, opt: Rounds): SCrypt =
        SCrypt(
          SCryptUtil.scrypt(pass.pass, math.pow(2, opt.rounds).toInt, DefaultSCryptR, DefaultSCryptP)
        )

      def checkPassword(pass: Password, hashed: SCrypt): Boolean =
        JSCrypt.check(pass.pass, hashed.hashed)
    }

  object SCryptAlgebra extends PWHashInterpreter[SCrypt]

  implicit object SCryptPasswordHasher
      extends PWHashPrograms[PasswordValidated, SCrypt](SCryptAlgebra, Rounds(DefaultSCryptN))(
        SCrypt.ScryptPasswordHasher
      )
}
