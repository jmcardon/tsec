package tsec.authentication

import tsec.mac.imports._

class CSRFTests extends CSRFSpec{

  testCSRFWithMac[HMACSHA1]
  testCSRFWithMac[HMACSHA256]
  testCSRFWithMac[HMACSHA384]
  testCSRFWithMac[HMACSHA512]

}
