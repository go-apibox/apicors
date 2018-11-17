package apicors

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-apibox/api"
	"github.com/go-apibox/utils"
)

type CORS struct {
	app      *api.App
	disabled bool
	inited   bool

	allowOrigins     []string
	allowCredentials bool
	maxAge           int

	actionMatcher *utils.Matcher
}

func NewCORS(app *api.App) *CORS {
	app.Error.RegisterGroupErrors("cors", ErrorDefines)

	cors := new(CORS)
	cors.app = app

	cfg := app.Config
	disabled := cfg.GetDefaultBool("apicors.disabled", false)

	cors.disabled = disabled
	if disabled {
		return cors
	}

	cors.init()
	return cors
}

func (co *CORS) init() {
	if co.inited {
		return
	}

	app := co.app
	cfg := app.Config
	allowOrigins := cfg.GetDefaultStringArray("apicors.allow_origins", []string{"*"})
	allowCredentials := cfg.GetDefaultBool("apicors.allow_credentials", false)
	actionWhitelist := cfg.GetDefaultStringArray("apicors.actions.whitelist", []string{"*"})
	actionBlacklist := cfg.GetDefaultStringArray("apicors.actions.blacklist", []string{})
	maxAge := cfg.GetDefaultInt("apicors.max_age", -1)

	matcher := utils.NewMatcher()
	matcher.SetWhiteList(actionWhitelist)
	matcher.SetBlackList(actionBlacklist)

	co.allowOrigins = allowOrigins
	co.allowCredentials = allowCredentials
	co.maxAge = maxAge
	co.actionMatcher = matcher
	co.inited = true
}

func (co *CORS) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if co.disabled {
		next(w, r)
		return
	}

	c, err := api.NewContext(co.app, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// check if action not required cors check
	action := c.Input.GetAction()
	if !co.actionMatcher.Match(action) {
		next(w, r)
		return
	}

	// CORS处理
	originAllowed := false
	rOrigin := r.Header.Get("Origin")
	var matchedOrigin string
	if rOrigin != "" {
		for _, allowOrigin := range co.allowOrigins {
			if allowOrigin == "*" || allowOrigin == rOrigin {
				originAllowed = true
				matchedOrigin = allowOrigin
				break
			}
		}
	} else {
		originAllowed = true
		matchedOrigin = strings.Join(co.allowOrigins, ",")
	}

	if originAllowed {
		if co.allowCredentials && matchedOrigin == "*" {
			matchedOrigin = rOrigin
		}
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Origin", matchedOrigin)

			rCorsMethods := r.Header.Get("Access-Control-Request-Method")
			if rCorsMethods != "" {
				w.Header().Set("Access-Control-Allow-Methods", rCorsMethods)
			}

			rCorsHeaders := r.Header.Get("Access-Control-Request-Headers")
			if rCorsHeaders != "" {
				w.Header().Set("Access-Control-Allow-Headers", rCorsHeaders)
			}

			if co.allowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if co.maxAge != -1 {
				w.Header().Set("Access-Control-Max-Age", strconv.Itoa(co.maxAge))
			}

			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			w.Header().Set("Access-Control-Allow-Origin", matchedOrigin)

			if co.allowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if co.maxAge != -1 {
				w.Header().Set("Access-Control-Max-Age", strconv.Itoa(co.maxAge))
			}
		}
	}

	// next middleware
	next(w, r)
}
