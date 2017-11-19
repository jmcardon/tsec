package tsec.libsodium

import org.scalatest.MustMatchers
import org.scalatest.prop.PropertyChecks
import tsec.TestSpec

trait SodiumSpec extends TestSpec with MustMatchers with PropertyChecks {
  implicit val sodium: ScalaSodium = ScalaSodium.getSodiumUnsafe
}
