package tsec.passwordhashers

import tsec.passwordhashers.core.{PWHashPrograms, PasswordValidated}

package object imports {

  /**
    * https://security.stackexchange.com/questions/17207/recommended-of-rounds-for-bcrypt
    * Default is 10 on most applications
    */
  val DefaultBcryptRounds = 10

  /**
    * https://crypto.stackexchange.com/questions/35423/appropriate-scrypt-parameters-when-generating-an-scrypt-hash
    */
  val DefaultSCryptN = 14
  val DefaultSCryptR = 8
  val DefaultSCryptP = 1

  /**
    * http://www.tarsnap.com/scrypt/scrypt-slides.pdf
    */
  val SCryptHardenedN = 18
  val SCryptHardnedR  = 8
  val SCryptHardenedP = 2
}
