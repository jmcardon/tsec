import fucc.all.encryption.passwordhashers.core.{BCrypt, SCrypt}
import fucc.all.encryption.passwordhashers.core.BCryptPasswordHasher._
import fucc.all.encryption.passwordhashers.defaults.ops._
import fucc.all.encryption.passwordhashers.hardenedDefaults._
import fucc.all.encryption.passwordhashers.core.SCryptPasswordHasher

implicit val hardened = SCryptPasswordHasher(HardenedDefaultSCrypt)

"hello".hash[BCrypt]

val scryptHash = "hello".hash[SCrypt]

"hello".check[SCrypt](scryptHash.right.get)