package http

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/joeyloman/rancher-fip-lb-controller/pkg/ipam"
	"github.com/sirupsen/logrus"
)

type Server struct {
	ipamClient      *ipam.Client
	clientSecret    string
	cluster         string
	project         string
	floatingIPPools []string
	username        string
	password        string
	sessions        map[string]time.Time
	sessionsMutex   sync.Mutex
}

func NewServer(ipamClient *ipam.Client, clientSecret, cluster, project string, floatingIPPools []string, username, password string) *Server {
	return &Server{
		ipamClient:      ipamClient,
		clientSecret:    clientSecret,
		cluster:         cluster,
		project:         project,
		floatingIPPools: floatingIPPools,
		username:        username,
		password:        password,
		sessions:        make(map[string]time.Time),
	}
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.username == "" && s.password == "" {
			next(w, r)
			return
		}

		cookie, err := r.Cookie("session_token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		sessionToken := cookie.Value

		s.sessionsMutex.Lock()
		defer s.sessionsMutex.Unlock()

		sessionExpiry, ok := s.sessions[sessionToken]
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if time.Now().After(sessionExpiry) {
			delete(s.sessions, sessionToken)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, err := template.New("login").Parse(loginTemplate)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == s.username && password == s.password {
			tokenBytes := make([]byte, 16)
			if _, err := rand.Read(tokenBytes); err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			sessionToken := hex.EncodeToString(tokenBytes)

			expiresAt := time.Now().Add(24 * time.Hour)

			s.sessionsMutex.Lock()
			s.sessions[sessionToken] = expiresAt
			s.sessionsMutex.Unlock()

			http.SetCookie(w, &http.Cookie{
				Name:    "session_token",
				Value:   sessionToken,
				Expires: expiresAt,
				Path:    "/",
			})

			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else {
			tmpl, err := template.New("login").Parse(loginTemplate)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			data := struct {
				Error string
			}{
				Error: "Unauthorized",
			}
			tmpl.Execute(w, data)
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	sessionToken := cookie.Value

	s.sessionsMutex.Lock()
	delete(s.sessions, sessionToken)
	s.sessionsMutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) Start(httpServerPort int) {
	http.HandleFunc("/", s.withAuth(s.handleFIPList))
	http.HandleFunc("/release", s.withAuth(s.handleRelease))
	http.HandleFunc("/remove", s.withAuth(s.handleRemove))
	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/logout", s.handleLogout)

	logrus.Infof("Starting HTTP server on :%d", httpServerPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", httpServerPort), nil); err != nil {
		logrus.Fatalf("failed to start http server: %s", err)
	}
}

func (s *Server) handleFIPList(w http.ResponseWriter, r *http.Request) {
	logrus.Info("Listing FIPs")

	fipList := &ipam.FIPListResponse{}

	for _, floatingIPPool := range s.floatingIPPools {
		fips, err := s.ipamClient.ListFIPs(s.clientSecret, s.cluster, s.project, floatingIPPool)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to list fips from pool %s: %s", floatingIPPool, err), http.StatusInternalServerError)
			return
		}
		if fips != nil {
			fipList.FloatingIPs = append(fipList.FloatingIPs, fips.FloatingIPs...)
		}
	}

	for i := range fipList.FloatingIPs {
		if fipList.FloatingIPs[i].Cluster == "" {
			fipList.FloatingIPs[i].Cluster = "Unassigned"
		}
		if fipList.FloatingIPs[i].ServiceNamespace == "" {
			fipList.FloatingIPs[i].ServiceNamespace = "Unassigned"
		}
		if fipList.FloatingIPs[i].ServiceName == "" {
			fipList.FloatingIPs[i].ServiceName = "Unassigned"
		}
	}

	tmpl, err := template.New("fipList").Parse(fipListTemplate)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse template: %s", err), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, fipList); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %s", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	logrus.Info("Releasing FIP")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// The `ReleaseFIP` function requires more parameters than the `DeleteFIP` function.
	// For now we will call the `DeleteFIP` for both actions until `ReleaseFIP` is updated.
	project := r.FormValue("project")
	cluster := r.FormValue("cluster")
	floatingippool := r.FormValue("floatingippool")
	servicenamespace := r.FormValue("servicenamespace")
	servicename := r.FormValue("servicename")
	ipaddr := r.FormValue("ipaddr")

	// Validate the form values
	formValues := map[string]string{
		"project":          project,
		"cluster":          cluster,
		"floatingippool":   floatingippool,
		"servicenamespace": servicenamespace,
		"servicename":      servicename,
		"ipaddr":           ipaddr,
	}

	for key, value := range formValues {
		if value == "" {
			http.Error(w, fmt.Sprintf("%s is a required field", key), http.StatusBadRequest)
			return
		}

		if len(value) > 253 {
			http.Error(w, fmt.Sprintf("%s is too long, maximum length is 253 characters", key), http.StatusBadRequest)
			return
		}
	}

	if net.ParseIP(ipaddr) == nil {
		http.Error(w, "invalid ip address format for ipaddr", http.StatusBadRequest)
		return
	}

	logrus.Infof("Releasing FIP %s from project %s", ipaddr, project)

	if err := s.ipamClient.ReleaseFIP(s.clientSecret, cluster, project, floatingippool, servicenamespace, servicename, ipaddr); err != nil {
		http.Error(w, fmt.Sprintf("failed to release fip: %s", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleRemove(w http.ResponseWriter, r *http.Request) {
	logrus.Info("Removing FIP")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	project := r.FormValue("project")
	ipaddr := r.FormValue("ipaddr")

	// Validate the form values
	formValues := map[string]string{
		"project": project,
		"ipaddr":  ipaddr,
	}

	for key, value := range formValues {
		if value == "" {
			http.Error(w, fmt.Sprintf("%s is a required field", key), http.StatusBadRequest)
			return
		}

		if len(value) > 253 {
			http.Error(w, fmt.Sprintf("%s is too long, maximum length is 253 characters", key), http.StatusBadRequest)
			return
		}
	}

	if net.ParseIP(ipaddr) == nil {
		http.Error(w, "invalid ip address format for ipaddr", http.StatusBadRequest)
		return
	}

	logrus.Infof("Removing FIP %s from project %s", ipaddr, project)

	if err := s.ipamClient.DeleteFIP(s.clientSecret, project, ipaddr); err != nil {
		http.Error(w, fmt.Sprintf("failed to remove fip: %s", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

const fipListTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Rancher FIP LB Controller - Floating IP List</title>
	<style>
		body { font-family: sans-serif; }
		table { border-collapse: collapse; }
		th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }
		tr:nth-child(even) { background-color: #f2f2f2; }
		button { margin-right: 5px; }
	</style>
</head>
<body>
    <h1>Rancher FIP LB Controller - Floating IPs</h1>
	<form action="/logout" method="post" style="margin-bottom: 1em;">
        <button type="submit">Logout</button>
    </form>
    <table border="1">
        <tr>
            <th>Project</th>
            <th>Cluster</th>
            <th>Service Namespace</th>
            <th>Service Name</th>
            <th>IP Address</th>
            <th>Actions</th>
        </tr>
        {{range .FloatingIPs}}
        <tr>
            <td>{{.Project}}</td>
            <td>{{.Cluster}}</td>
            <td>{{.ServiceNamespace}}</td>
            <td>{{.ServiceName}}</td>
            <td>{{.IPAddress}}</td>
            <td>
                <form action="/release" method="post" style="display:inline;">
                    <input type="hidden" name="project" value="{{.Project}}">
					<input type="hidden" name="cluster" value="{{.Cluster}}">
					<input type="hidden" name="floatingippool" value="{{.FloatingIPPool}}">
					<input type="hidden" name="servicenamespace" value="{{.ServiceNamespace}}">
					<input type="hidden" name="servicename" value="{{.ServiceName}}">
                    <input type="hidden" name="ipaddr" value="{{.IPAddress}}">
                    <button type="submit" {{if eq .Cluster "Unassigned"}}disabled{{end}} onclick="return confirm('Are you sure you want to release FloatingIP {{.IPAddress}} from cluster {{.Cluster}}?');">Release from cluster</button>
                </form>
                <form action="/remove" method="post" style="display:inline;">
                    <input type="hidden" name="project" value="{{.Project}}">
                    <input type="hidden" name="ipaddr" value="{{.IPAddress}}">
                    <button type="submit" {{if ne .Cluster "Unassigned"}}disabled{{end}} onclick="return confirm('Are you sure you want to remove FloatingIP {{.IPAddress}} from project {{.Project}}?');">Remove from project</button>
                </form>
            </td>
        </tr>
        {{end}}
    </table>
	<p>
	<b>WARNING:</b><br>
	This web application let you manage all FloatingIPs of all clusters which are assigned to the same project this cluster it a part of.
	You could harm other clusters if you are not careful!<br>
	The proper way to release a FloatingIP from a cluster is to just delete the Service (Load Balancer) object inside the cluster.
	If that is not possible, you can use this web application to release the FloatingIP and remove it from the project.
	</p>
</body>
</html>
`

const loginTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Rancher FIP LB Controller Login</title>
	<style>
		body { font-family: sans-serif; }
	</style>
</head>
<body>
    <h1>Rancher FIP LB Controller Login</h1>
	{{if .Error}}
		<p style="color: red;">{{.Error}}</p>
	{{end}}
    <form method="post" action="/login">
        <div>
            <label for="username">Username:</label>
            <input type="text" id="username" name="username">
        </div>
        <div style="margin-top: 0.5em;">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password">
        </div>
        <div style="margin-top: 1em;">
            <input type="submit" value="Login">
        </div>
    </form>
</body>
</html>
`
