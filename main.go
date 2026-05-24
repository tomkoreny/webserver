package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/graphql-go/graphql"
	"github.com/lordpuma/webserver/Types"
	"github.com/lordpuma/webserver/database"
	"github.com/rs/cors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var schema graphql.Schema

func init() {
	var err error
	if err != nil {
		panic(err)
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var id int
		if r.Header.Get("token") != "" {
			err := database.Db.QueryRow("SELECT user_id FROM logins WHERE token = ?", r.Header.Get("token")).Scan(&id)
			if err == sql.ErrNoRows {
				resp, _ := json.Marshal(map[string]interface{}{"error": "bad_token"})
				w.Write(resp)
				return
			}
			if err != nil {
				resp, _ := json.Marshal(map[string]interface{}{"error": "auth_error"})
				w.WriteHeader(http.StatusInternalServerError)
				w.Write(resp)
				return
			}
			if id == 0 {
				resp, _ := json.Marshal(map[string]interface{}{"error": "bad_token"})
				w.Write(resp)
			} else {
				ctx := context.WithValue(context.Background(), "user_id", id)
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		} else {
			resp, _ := json.Marshal(map[string]interface{}{"error": "no_header"})
			w.Write(resp)
		}
	})
}

func queryHand() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]interface{}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Fprintf(w, "%s", err)
		}
		var m interface{}
		err = json.Unmarshal(body, &m)
		if err != nil {
			fmt.Fprintf(w, "%s", err)
		}

		q := m.(map[string]interface{})["query"].(string)

		if m.(map[string]interface{})["variables"] != nil {
			v = m.(map[string]interface{})["variables"].(map[string]interface{})
		}

		params := graphql.Params{Schema: schema, RequestString: q, Context: r.Context(), VariableValues: v}
		ret := graphql.Do(params)
		if len(ret.Errors) > 0 {
			log.Fatalf("failed to execute graphql operation, errors: %+v", ret.Errors)
		}

		resp, _ := json.Marshal(ret)
		fmt.Fprintf(w, "%s", resp)

	})
}

var page = []byte(`
<!DOCTYPE html>
<html>
	<head>
		<title>Intranet backend</title>
	</head>
	<body>
		Are you lost?
	</body>
</html>
`)

func randToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func main() {

	dbUrl := os.Getenv("JAWSDB_URL")
	if dbUrl == "" {
		dbUrl = "mysql://root:pass@/database"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}

	u, err := url.Parse(dbUrl)
	if err != nil {
		panic(err)
	}

	hostUrl := ""
	if (u.Host) != "" {
		hostUrl = "tcp(" + u.Host + ")"
	}

	dsn := u.User.String() + "@" + hostUrl + u.Path
	params := u.Query()
	params.Set("allowNativePasswords", "true")
	if encodedParams := params.Encode(); encodedParams != "" {
		dsn += "?" + encodedParams
	}

	db, err := sql.Open(u.Scheme, dsn)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()
	database.Connect(db)

	rootQuery := graphql.ObjectConfig{Name: "RootQuery", Fields: Types.RootQuery}
	rootMutation := graphql.ObjectConfig{Name: "RootMutation", Fields: Types.RootMutation}
	schemaConfig := graphql.SchemaConfig{Query: graphql.NewObject(rootQuery), Mutation: graphql.NewObject(rootMutation)}
	schema, err = graphql.NewSchema(schemaConfig)
	if err != nil {
		log.Fatalf("failed to create new schema, error: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(page)
	}))

	mux.HandleFunc("/races/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		var m []interface{}
		err = json.Unmarshal(body, &m)
		fmt.Println(m)
		var id int
		database.Db.QueryRow("SELECT id FROM races	 WHERE active = 1 LIMIT 1").Scan(&id)
		for _, e := range m {
			_, err := database.Db.Exec("INSERT INTO results (name, time, race_id) VALUES (?, ?, ?)", e.(map[string]interface{})["name"], e.(map[string]interface{})["time"], id)
			if err != nil {
				panic(err)
			}
			fmt.Println(e)
		}
		resp, err := json.Marshal(map[string]interface{}{"error": err})
		w.Write(resp)
	}))

	mux.Handle("/query", authMiddleware(queryHand()))

	mux.HandleFunc("/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		var m interface{}
		err = json.Unmarshal(body, &m)

		if m != nil {
			if m.(map[string]interface{})["pass"] != nil && m.(map[string]interface{})["user"] != nil {
				h := md5.New()
				io.WriteString(h, m.(map[string]interface{})["pass"].(string))
				var username string
				var pass sql.NullString
				var id []uint8
				rows, err := database.Db.Query("select id, username, pass from users")
				if err != nil {
					log.Fatal(err)
				}
				defer rows.Close()
				for rows.Next() {
					err := rows.Scan(&id, &username, &pass)
					if err != nil {
						log.Fatal(err)
					}
					if strings.ToLower(m.(map[string]interface{})["user"].(string)) == strings.ToLower(username) {
						token := randToken()
						if pass.Valid {
							passhash := new(bytes.Buffer)
							fmt.Fprintf(passhash, "%x", h.Sum(nil)) //cast pass hash to var
							if passhash.String() == pass.String {
								_, err := database.Db.Exec("INSERT INTO logins (user_id, token) VALUES (?, ?)", id, token) //Save Token to db
								if err != nil {
									panic(err)
								}
								resp, err := json.Marshal(map[string]interface{}{"token": token})
								w.Write(resp) //USER IS LOGIN, send him token
								return
							}
						} else {
							_, err := database.Db.Exec("INSERT INTO logins (user_id, token) VALUES (?, ?)", id, token) //Save Token to db
							if err != nil {
								panic(err)
							}
							resp, err := json.Marshal(map[string]interface{}{"token": token, "first": true})
							w.Write(resp) //USER IS LOGIN, send him token
							return
						}

					}
				}
				err = rows.Err()
				resp, err := json.Marshal(map[string]interface{}{"error": "unknown-user-or-pass"})
				w.Write(resp)
				return
			}
		}
		resp, err := json.Marshal(map[string]interface{}{"error": err})
		w.Write(resp)
	}))

	mux.HandleFunc("/logout", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("token") != "" {
			_, err := database.Db.Exec("DELETE FROM logins WHERE token = ?", r.Header.Get("token")) //delete token
			if err != nil {
				panic(err)
			}
			resp, _ := json.Marshal(map[string]interface{}{"success": true})
			w.Write(resp)
		} else {
			resp, _ := json.Marshal(map[string]interface{}{"error": "no_header"})
			w.Write(resp)
		}

	}))

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://intranet-c2bbb.firebaseapp.com", "https://intranet-c2bbb.web.app", "https://intranet.lempls.com", "http://localhost:4200", "https://poepoe-shifts.firebaseapp.com", "https://poepoe.lempls.com"},
		AllowedMethods:   []string{"GET", "POST", "PUT"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})
	fmt.Println("APP FUCKING INITIALIZED!")
	log.Fatal(http.ListenAndServe(":"+port, c.Handler(mux)))

}
