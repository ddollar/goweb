package goweb

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/bradrydzewski/go.auth"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
)

type Goweb struct {
	Authorized []string
	Port       string
	Secret     string

	Router *mux.Router
	Server *negroni.Negroni

	templates map[string]*template.Template
}

func New(secret string) *Goweb {
	g := &Goweb{Secret: secret}

	g.templates = make(map[string]*template.Template)

	g.Router = mux.NewRouter()
	g.Server = negroni.Classic()

	g.Router.Handle("/auth/login", auth.OpenId("https://accounts.google.com/o/openid2/auth")).Methods("GET")
	g.Router.HandleFunc("/auth/logout", logout)

	g.Server.Use(negroni.HandlerFunc(g.authorize))
	g.Server.UseHandler(g.Router)

	return g
}

func (g *Goweb) Run(addr string) {
	auth.Config.CookieName = "id"
	auth.Config.CookieExp = time.Hour * 24 * 30
	auth.Config.CookieSecret = []byte(g.Secret)
	auth.Config.CookieSecure = false
	auth.Config.LoginSuccessRedirect = "/"

	g.Server.Run(addr)
}

func (g *Goweb) AddTemplate(page string, names ...string) {
	files := []string{"templates/layout.tmpl", fmt.Sprintf("templates/%s.tmpl", page)}
	for _, name := range names {
		files = append(files, fmt.Sprintf("templates/%s.tmpl", name))
	}
	funcmap := template.FuncMap{
		"join": func(s []string, t string) string {
			return strings.Join(s, t)
		},
	}
	g.templates[page] = template.Must(template.New("layout").Funcs(funcmap).ParseFiles(files...))
}

func (g *Goweb) ExecuteTemplate(rw http.ResponseWriter, page string, context interface{}) {
	if err := g.templates[page].Execute(rw, context); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func (g *Goweb) authorize(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if r.URL.Path == "/auth/login" {
		next(rw, r)
		return
	}

	user, _ := auth.GetUserCookie(r)

	if user == nil {
		http.Redirect(rw, r, "/auth/login", http.StatusFound)
		return
	}

	for _, admin := range g.Authorized {
		if admin == user.Id() {
			next(rw, r)
			return
		}
	}

	http.Redirect(rw, r, "/auth/login", http.StatusFound)
}

func logout(rw http.ResponseWriter, r *http.Request) {
	auth.DeleteUserCookie(rw, r)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}
