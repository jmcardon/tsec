package fucc.all.encryption.passwordhashers

import com.lambdaworks.crypto.{SCryptUtil => JSCrypt}
import fucc.all.encryption.passwordhashers.core.{
  Password,
  PasswordHasher,
  PasswordOpt,
  SCrypt
}

package object hardenedDefaults {

  /**
   * http://www.tarsnap.com/scrypt/scrypt-slides.pdf
   */
  val S_HARDENED_N: Int = math.pow(2, 20).toInt
  val S_HARDENED_r = 8
  val S_HARDENED_p = 2

  implicit lazy val HardenedDefaultSCrypt = new PasswordHasher[SCrypt] {
    def hashPw(pass: Password, opt: PasswordOpt): SCrypt =
      SCrypt(
        JSCrypt.scrypt(pass.pass, S_HARDENED_N, S_HARDENED_r, S_HARDENED_p))

    def checkPassword(pass: Password, hashed: SCrypt): Boolean =
      JSCrypt.check(pass.pass, hashed.hashed)
  }
}
