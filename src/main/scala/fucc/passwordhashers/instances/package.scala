package fucc.passwordhashers

package object instances {
  /**
   * https://security.stackexchange.com/questions/17207/recommended-of-rounds-for-bcrypt
   * Default is 10 on most applications
   */
  val DefaultBcryptRounds = 10


  /**
   * https://crypto.stackexchange.com/questions/35423/appropriate-scrypt-parameters-when-generating-an-scrypt-hash
   */
  val DefaultSCryptP = 2
  val DefaultSCryptN = 16384
  val DefaultSCryptR = 8

  /**
   * http://www.tarsnap.com/scrypt/scrypt-slides.pdf
   */
  val SCryptHardenedN: Int = math.pow(2, 18).toInt
  val SCryptHardnedR = 8
  val SCryptHardenedP = 1
}
