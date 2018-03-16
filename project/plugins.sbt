logLevel := Level.Warn
addSbtPlugin("com.lucidchart" % "sbt-scalafmt" % "1.15")
addSbtPlugin("org.foundweekends" % "sbt-bintray" % "0.5.1")
addSbtPlugin("com.47deg"  % "sbt-microsites" % "0.7.4")
addSbtPlugin("org.tpolecat" % "tut-plugin" % "0.6.2")
addSbtPlugin("com.typesafe.sbt" % "sbt-ghpages" % "0.6.2")
addSbtPlugin("pl.project13.scala" % "sbt-jmh" % "0.3.2")
addSbtPlugin("com.timushev.sbt" % "sbt-updates" % "0.3.3")

libraryDependencies ++= List(
  //"org.scalameta" %% "scalameta" % "2.1.2",
  "com.geirsson" %% "scalafmt-core" % "1.3.0",
  "com.geirsson" %% "scalafmt-cli" % "1.3.0",
)

unmanagedJars in Compile ++= tsec.build.SunShine.`tools.jar`.toSeq

sources in Compile ++= {
  if (tsec.build.SunShine.canWeUseToolsDotJar_?)
    file("project/boiler/gensodium.scala").getAbsoluteFile :: Nil
  else Nil
}