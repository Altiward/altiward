- `upgrade.sh` downloads the release when you give it a version: `./upgrade.sh 1.0.2`
  fetches the five files it needs from GitHub into `releases/1.0.2/` in the deployment
  directory, using `curl`, which goes through `HTTPS_PROXY` if it's set, then checks and
  installs them as before. A failed download stops before anything changes and names the
  file. A directory of release files still works, for servers without internet access.
  The console's upgrade notice shows the one-line command.
