- With Intune connected, the console shows what Intune says. **Enrollments** gives each
  key an **Intune check** (from the new `mdm_check`), says that a match isn't proof,
  warns before you approve a key sent with the device ID of another Mac or device, and
  tags a Mac Intune doesn't list **Not in Intune**. **Fleet** shows a Mac's primary user
  and last Intune check-in, and a panel of the Macs Intune manages that have never
  reported to Altiward. A new **Settings › MDM** tab shows the connection, its last sync
  and error, how many active Macs checked since Intune was connected matched it and how
  many haven't been checked yet, with a **Require an Intune match** switch for admins that
  asks first while some haven't matched or haven't been checked. Viewers see the Intune
  records too: serial, name, primary user and last check-in, never the device IDs.
