- With Intune connected, the console shows what Intune says. **Enrollments** gives each
  key an **Intune check** (from the new `mdm_check`) and tags a Mac Intune doesn't list
  **Not in Intune**. **Fleet** shows a Mac's primary user and last Intune check-in, and a
  panel of the Macs Intune manages that have never reported to Altiward. A new
  **Settings › MDM** tab shows the connection, its last sync and error, and how many
  active Macs matched Intune when they enrolled, with a **Require an Intune match**
  switch for admins that asks first when some haven't matched. Viewers see the Intune
  records too: serial, name, primary user and last check-in, never the device IDs.
