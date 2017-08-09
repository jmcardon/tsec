package tsec.cipher.instances.mode

sealed trait CCM
object CCM extends WithModeTag[CCM]("CCM") with DefaultModeKeySpec[CCM]
