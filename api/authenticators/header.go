package authenticators

import (
	"context"
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/sirupsen/logrus"
	"www.velocidex.com/golang/velociraptor/acls"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/json"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/users"
)

// Implement header authentication.
type HeaderAuthenticator struct {
	config_obj      *config_proto.Config
	username_header string
	secret_header   string
	secret_value    string
	logoff_url      string
}

// Header auth does not need any special handlers.
func (self *HeaderAuthenticator) AddHandlers(mux *http.ServeMux) error {
	return nil
}

func (self *HeaderAuthenticator) AddLogoff(mux *http.ServeMux) error {
	base := self.config_obj.GUI.BasePath
	mux.Handle(base+"/logoff", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if self.logoff_url != "" {
			http.Redirect(w, r, self.logoff_url, http.StatusTemporaryRedirect)
			return
		}

		http.Error(w, "Not authorized", http.StatusUnauthorized)
	}))

	return nil
}

func (self *HeaderAuthenticator) IsPasswordLess() bool {
	return true
}

func (self *HeaderAuthenticator) AuthenticateUserHandler(
	parent http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSRF-Token", csrf.Token(r))

		// The secret is given in a request header via secret_header.
		secret := strings.TrimSpace(r.Header.Get(self.secret_header))
		if secret != self.secret_value {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// The username is given in a request header via username_header.
		username := strings.TrimSpace(r.Header.Get(self.username_header))
		if username == "" {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// Get the full user record with hashes so we can
		// verify it below.
		user_record, err := users.GetUserWithHashes(self.config_obj, username)
		if err != nil {
			logger := logging.GetLogger(self.config_obj, &logging.Audit)
			logger.WithFields(logrus.Fields{
				"username": username,
				"status":   http.StatusUnauthorized,
			}).Error("Unknown username")

			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		// Must have at least reader.
		perm, err := acls.CheckAccess(self.config_obj, username, acls.READ_RESULTS)
		if !perm || err != nil || user_record.Locked || user_record.Name != username {
			logger := logging.GetLogger(self.config_obj, &logging.Audit)
			logger.WithFields(logrus.Fields{
				"username": username,
				"status":   http.StatusUnauthorized,
			}).Error("Unauthorized username")

			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		// Checking is successful - user authorized. Here we
		// build a token to pass to the underlying GRPC
		// service with metadata about the user.
		user_info := &api_proto.VelociraptorUser{
			Name: username,
		}

		// Must use json encoding because grpc can not handle
		// binary data in metadata.
		serialized, _ := json.Marshal(user_info)
		ctx := context.WithValue(
			r.Context(), constants.GRPC_USER_CONTEXT, string(serialized))

		// Need to call logging after auth so it can access
		// the USER value in the context.
		GetLoggingHandler(self.config_obj)(parent).ServeHTTP(
			w, r.WithContext(ctx))
	})
}
