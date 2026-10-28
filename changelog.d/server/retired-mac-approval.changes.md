- A new key for a retired Mac now always waits for approval, even with re-enrolment
  approval off (#193). Pending enrolment, retries and rejection keep the Mac retired;
  approving the key restores it. A replaced key used again still restores the Mac through
  the existing contest alert. The key-revoke dialogue now explains that admin rights stay
  in place and directs you to **Admins now > Revoke** before revoking the key. The install
  guide also explains that changing enrolment limits does not reset an agent's current
  `Retry-After` wait; restarting the agent does.
