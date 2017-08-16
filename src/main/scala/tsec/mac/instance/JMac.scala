package tsec.mac.instance

import shapeless.{::, HNil}
import tsec.mac.MacKey
import tsec.mac.core.{MacAlgebra, MacPrograms}
import cats.implicits._

class JMac[A: MacTag](
    algebra: JMacInterpreter[A],
    gen: MacPrograms.MacAux[A, Array[Byte] :: HNil]
) extends MacPrograms[Either[MacError, ?], A, MacKey](algebra, gen)

object JMac {
    def getInstance[A: MacTag](implicit gen: MacPrograms.MacAux[A, Array[Byte]::HNil]) = new JMac[A](new JMacInterpreter[A], gen)
}