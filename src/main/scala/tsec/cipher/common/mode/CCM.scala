package tsec.cipher.common.mode

sealed trait CCM
object CCM extends DefaultModeKeySpec[CCM]("CCM")
