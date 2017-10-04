package tsec

import tsec.cipher.asymmetric.imports._
import tsec.cipher.asymmetric.padding.OAEPWithSha512andMGF1Padding
import tsec.cipher.common.padding._

class JCAAsymmetricCipherTests extends AsymmetricSpec {

  cipherTest[RSA2048, NoPadding]
  cipherTest[RSA3072, NoPadding]
  cipherTest[RSA4096, NoPadding]

  cipherTest[RSA2048, OAEPWithSha512andMGF1Padding]
  cipherTest[RSA3072, OAEPWithSha512andMGF1Padding]
  cipherTest[RSA4096, OAEPWithSha512andMGF1Padding]

}
