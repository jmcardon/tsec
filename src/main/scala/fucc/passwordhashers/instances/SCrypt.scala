package fucc.passwordhashers.instances

import com.lambdaworks.crypto.{SCryptUtil => JSCrypt}
import fucc.passwordhashers.core._

case class SCrypt(hashed: String)

object SCrypt {
  implicit lazy val ScryptPasswordHasher: PasswordHasher[SCrypt] =
    new PasswordHasher[SCrypt] {
      def hashPw(pass: Password, opt: PasswordOpt): SCrypt =
        SCrypt(
          JSCrypt
            .scrypt(pass.pass, DefaultSCryptN, DefaultSCryptR, DefaultSCryptP))

      def checkPassword(pass: Password, hashed: SCrypt): Boolean =
        JSCrypt.check(pass.pass, hashed.hashed)
    }

  object SCryptAlgebra extends ImplAlgebra[SCrypt]

  implicit object SCryptPasswordHasher
      extends PWHashPrograms[PasswordValidated, SCrypt](
        SCryptAlgebra,
        Right(Rounds(DefaultSCryptN)))(SCrypt.ScryptPasswordHasher)
}
