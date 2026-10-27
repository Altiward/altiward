- If storing a `rotated_key_used` alert failed, the server had already revoked the Mac's
  current key and marked the use as reported, so an admin saw a revoked key with no alert,
  and the key's other uses that day raised none. The alert is now stored in the same step:
  if it can't be, nothing changes, and the key's next use is checked again.
