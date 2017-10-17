object PasswordHashingExamples {

  import tsec.common._
  import tsec.passwordhashers._
  import tsec.passwordhashers.imports._

  /** For password hashers, you have three options: BCrypt, SCrypt and HardenedScrypt
    * (Which is basically scrypt but with much more secure parameters, but a lot slower)
    */
  val bcryptHash: BCrypt                 = "hiThere".hashPassword[BCrypt]
  val scryptHash: SCrypt                 = "hiThere".hashPassword[SCrypt]
  val hardenedScryptHash: HardenedSCrypt = "hiThere".hashPassword[HardenedSCrypt]

  /** To Validate, you can check against a hash! */
  val check: Boolean = "hiThere".checkWithHash[BCrypt](bcryptHash)

  /*
  To Cast a hash to a plain string
   */
  bcryptHash.asString
  /*
  To cast a hash to a plain string
   */
  "hi".toStringRepr[BCrypt]

}
