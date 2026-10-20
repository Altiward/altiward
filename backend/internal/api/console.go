package api

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// consoleCSP keeps the console to its own origin: its scripts, styles, fonts and API
// calls all come from here, and no other site may frame it. With the update check on, the
// console may also ask GitHub's API for the release list, and nothing else there.
func consoleCSP(updateCheck bool) string {
	connect := "'self'"
	if updateCheck {
		connect += " " + GitHubAPI
	}
	return "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"font-src 'self'; connect-src " + connect + "; object-src 'none'; base-uri 'none'; form-action 'self'; " +
		"frame-ancestors 'none'"
}

// GitHubAPI is where the console's update check asks for releases (ALTIWARD_UPDATE_CHECK).
const GitHubAPI = "https://api.github.com"

// WithConsole serves the built console (console/dist) from the API's origin, so the
// browser sees one origin and the API needs no CORS, as with Vite's proxy in development.
// /v1/ and /healthz stay with api; every other GET is a console file, or index.html for
// the console's own routes. updateCheck lets the console reach GitHub's API (consoleCSP).
func WithConsole(api http.Handler, dist fs.FS, updateCheck bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/v1/", api)
	mux.Handle("/healthz", api)
	mux.Handle("/", consoleHandler(dist, consoleCSP(updateCheck)))
	return mux
}

// CheckConsole reports whether dist looks like a console build.
func CheckConsole(dist fs.FS) error {
	if _, err := fs.Stat(dist, "index.html"); err != nil {
		return errors.New("no index.html: build the console first (make console-build)")
	}
	return nil
}

func consoleHandler(dist fs.FS, csp string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if info, err := fs.Stat(dist, name); name == "" || err != nil || info.IsDir() {
			// A missing file is a 404; a path without an extension is one of the
			// console's routes, which the app resolves from index.html.
			if name != "" && path.Ext(name) != "" {
				http.NotFound(w, r)
				return
			}
			name = "index.html"
		}
		switch {
		case name == "index.html":
			// Always revalidated, so a deploy reaches open consoles on their next load.
			h.Set("Cache-Control", "no-cache")
		case strings.HasPrefix(name, "assets/"):
			// Vite puts a content hash in every asset name.
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			h.Set("Cache-Control", "public, max-age=3600")
		}
		serveFile(w, r, dist, name)
	})
}

// serveFile serves name without http.ServeFileFS's redirect of /index.html to the
// directory, which would loop for the console's routes.
func serveFile(w http.ResponseWriter, r *http.Request, dist fs.FS, name string) {
	f, err := dist.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, name, info.ModTime(), rs)
}
