- Signing out of the console can also sign people out of Entra ID. Set
  `ALTIWARD_OIDC_PROVIDER_SIGN_OUT=true` and register `https://<console hostname>/signed-out`
  as a redirect URI in the app registration. The setting is off by default, and the server
  refuses it unless the single sign-on issuer is Entra ID's. `POST /v1/auth/logout` then
  answers 200 with the provider's sign-out address instead of 204.
