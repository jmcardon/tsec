package tsec.signature.jca

import java.security.spec.ECGenParameterSpec

protected[tsec] trait ECCurve[A] {
  protected val defaultCurve: String
  def keySpecFromCurve: ECGenParameterSpec = new ECGenParameterSpec(defaultCurve)
}
