package api4

import (
	"net/http"

	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/web"
)

func requireQueryParam(name string) func(f web.ContextHandlerFunc) web.ContextHandlerFunc {
	return func(f web.ContextHandlerFunc) web.ContextHandlerFunc {
		return func(c *web.Context, w http.ResponseWriter, r *http.Request) {
			val := r.URL.Query().Get(name)
			if val == "" {
				c.Err = model.NewAppError(
					"",
					"api.error.query_presence",
					map[string]interface{}{"key": name, "val": val},
					"",
					http.StatusNotImplemented,
				)
				return
			}
			f(c, w, r)
		}
	}
}

func requireQueryInSet(name string, set []string) func(f web.ContextHandlerFunc) web.ContextHandlerFunc {
	return func(f web.ContextHandlerFunc) web.ContextHandlerFunc {
		return func(c *web.Context, w http.ResponseWriter, r *http.Request) {
			val := r.URL.Query().Get(name)
			inSet := false
			for _, setVal := range set {
				if setVal == val {
					inSet = true
				}
			}
			if !inSet {
				c.Err = model.NewAppError(
					"",
					"api.error.required_set",
					map[string]interface{}{"key": name, "val": val, "set": set},
					"",
					http.StatusNotImplemented,
				)
				return
			}
			f(c, w, r)
		}
	}
}

func requireSystemPermissions(permissions ...*model.Permission) func(f web.ContextHandlerFunc) web.ContextHandlerFunc {
	return func(f web.ContextHandlerFunc) web.ContextHandlerFunc {
		return func(c *web.Context, w http.ResponseWriter, r *http.Request) {
			for _, permissionID := range permissions {
				if !c.App.SessionHasPermissionTo(*c.App.Session(), permissionID) {
					c.SetPermissionError(permissionID)
					return
				}
			}
			f(c, w, r)
		}
	}
}

func requireLicenseFeatures(features []string) func(f web.ContextHandlerFunc) web.ContextHandlerFunc {
	return func(f web.ContextHandlerFunc) web.ContextHandlerFunc {
		return func(c *web.Context, w http.ResponseWriter, r *http.Request) {
			featureMap := c.App.License().Features.ToMap()
			for _, feature := range features {
				val, ok := featureMap[feature]
				if !ok || !val.(bool) {
					c.Err = model.NewAppError(
						"",
						"api.error.required_license_feature",
						map[string]interface{}{"feature": feature},
						"",
						http.StatusNotImplemented,
					)
					return
				}
			}
			f(c, w, r)
		}
	}
}

func requireSession() func(f web.ContextHandlerFunc) web.ContextHandlerFunc {
	return func(f web.ContextHandlerFunc) web.ContextHandlerFunc {
		return func(c *web.Context, w http.ResponseWriter, r *http.Request) {
			c.SessionRequired()
			c.MfaRequired()
			f(c, w, r)
		}
	}
}
