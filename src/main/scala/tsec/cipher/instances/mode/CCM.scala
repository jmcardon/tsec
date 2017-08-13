package tsec.cipher.instances.mode

sealed trait CCM
object CCM extends DefaultModeKeySpec[CCM]("CCM")
