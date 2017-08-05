package fucc.all.encryption.passwordhashers.defaults

import fucc.all.encryption.passwordhashers.core.{BCrypt, Password, PasswordValidated}

package object ops {

  implicit class Hasher(val password: String) extends AnyVal {

    def hash(implicit passwordHasher: BCryptPasswordHasher): PasswordValidated[BCrypt] = {
      passwordHasher.hash(Password(password))
    }

    def check(hash: BCrypt)(implicit passwordHasher: BCryptPasswordHasher) = {
      passwordHasher.checkHashed(Password(password),hash)
    }

  }

}
