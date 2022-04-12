package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/kataras/go-sessions"
)

// var tpl *template.Template

var db *sql.DB
var err error

// Users
type user struct {
	ID       int
	Username string
	Name     string
	Password string
}

// Report
type report struct {
	Merchant_name string `json:"merchant_name"`
	Outlet_name   string `json:"outlet_name"`
	Omzet         string `json:"omzet"`
	Date_create   string `json:"date_create"`
}

//Merchants
type Merchants struct {
	ID            int64     `json:"id"`
	Merchant_name string    `json:"merchant_name"`
	Created_at    time.Time `json:"created_at"`
	Created_by    int64     `json:"created_by"`
	Updated_at    time.Time `json:"updated_at"`
	Updated_by    int64     `json:"updated_by"`
}

//Outlets
type Outlet struct {
	ID          int64     `json:"id"`
	Merchant_id int64     `json:"merchant_id"`
	Outlet_name string    `json:"outlet_name"`
	Created_at  time.Time `json:"created_at"`
	Created_by  int64     `json:"created_by"`
	Updated_at  time.Time `json:"updated_at"`
	Updated_by  int64     `json:"updated_by"`
}

//Transactions
type Transactions struct {
	ID          int64     `json:"id"`
	Merchant_id int64     `json:"merchant_id"`
	Outlet_id   int64     `json:"outlet_id"`
	Bill_total  float64   `json:"bill_total"`
	Created_at  time.Time `json:"created_at"`
	Created_by  int64     `json:"created_by"`
	Updated_at  time.Time `json:"updated_at"`
	Updated_by  int64     `json:"updated_by"`
}

type (
	Area struct {
		ID        int64
		AreaValue int64
		AreaType  string
	}
)

// func(_r*AreaRepository) InsertArea(param1 int32, param2 int64, types []string, ar *Model.Area) (err error){
// 	inst := _r.DB.Model(ar)
// 	// Var area int
// 	// area = 0
// 	switch types {
// 		case 'persegi panjang':
// 			area = params1 * param2
// 			ar.AreaValue = area
// 			ar.AreaType = 'persegi panjang'
// 			err = _r.DB.create(&ar).Error
// 			if err != nil{
// 				return err
// 			}
// 		case 'persegi':
// 			var area = param1*param2
// 			ar.AreaValue = area
// 			ar.AreaType = 'persegi'
// 			err = _r.DB.create(&ar).Error
// 			if err != nil{
// 				return err
// 			}
// 		case 'segitiga':
// 			area = 0.5 * (param1 * param2)
// 			ar.AreaValue = area
// 			ar.AreaType = 'segitiga'
// 			err = _r.DB.create(&ar).Error
// 			if err != nil{
// 				return err
// 			}
// 	}
// }

// Result adl array dari produk
type Result struct {
	Code    int         `json:"code"`
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
}

var SECRET = []byte("tes-super-secret-auth-key")

func CreateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour).Unix()

	tokenStr, err := token.SignedString(SECRET)

	if err != nil {
		fmt.Printf(err.Error())
		return "", err
	}

	return tokenStr, nil
}

func ValidateJWT(next func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Header["Token"] != nil {
			token, err := jwt.Parse(r.Header["Token"][0], func(t *jwt.Token) (interface{}, error) {
				_, ok := t.Method.(*jwt.SigningMethodHMAC)
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Code: 401, Message: Not Authorized"))
				}
				return SECRET, nil
			})

			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Code: 401, Message: Not Authorized :" + err.Error()))
			}

			if token.Valid {
				next(w, r)
			}
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Code: 401, Message: Not Authorized"))
		}
	})
}

func GetJwt(w http.ResponseWriter, r *http.Request) {
	username, password, _ := r.BasicAuth()

	users := QueryUser(username)

	// hash md5
	hash := md5.New()
	hash.Write([]byte(password))
	encodepass := hex.EncodeToString(hash.Sum(nil))

	if username == users.Username {
		if users.Password == encodepass {
			token, err := CreateJWT()
			if err != nil {
				return
			}
			fmt.Fprintf(w, token)
		} else {
			return
		}
	}
}

/*
	response ketika api login berhasil
*/
func homeApi(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Code: 200, Message: Login Successfully")
}

/*
	koneksi ke database
	setting : db, err = sql.Open("mysql", "username:password@tcp(hostname)/nama_db")
*/
func connect_db() {
	db, err = sql.Open("mysql", "root:Bee123456!@tcp(127.0.0.1)/go_majoo")
	if err != nil {
		log.Println("Koneksi Gagal", err)
	} else {
		log.Println("Koneksi Berhasil")
	}
}

/*
	simpan routes
*/
func routes() {
	http.HandleFunc("/", home)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.Handle("/getreport", ValidateJWT(getReport))

	//for api
	http.Handle("/api", ValidateJWT(homeApi))
	http.HandleFunc("/jwt", GetJwt)
}

/*
	untuk login user
	Status 302 = pengalihan URL
*/
func login(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	if len(session.GetString("username")) != 0 && checkErr(w, r, err) {
		http.Redirect(w, r, "/", 302)
	}
	if r.Method != "POST" {
		http.ServeFile(w, r, "views/login.html")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	users := QueryUser(username)

	// hash md5
	hash := md5.New()
	hash.Write([]byte(password))
	encodepass := hex.EncodeToString(hash.Sum(nil))

	if users.Password == encodepass {
		//login success
		session := sessions.Start(w, r)
		session.Set("username", users.Username)
		session.Set("name", users.Name)
		http.Redirect(w, r, "/", 302)
	} else {
		//login failed
		http.Redirect(w, r, "/login", 302)
	}

}

/**
API to get omzet bulanan
*/
func getReport(w http.ResponseWriter, r *http.Request) {

	// query := QueryGetOmzet("2021-11-01", "2021-11-30")
	query := ReadData()

	res := Result{Code: 200, Data: query, Message: "sukses get data"}
	result, err := json.Marshal(res)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

/*
	monthlyReport untuk get laporan Omset bulanan
*/
func QueryGetOmzet(start_date string, end_date string) report {
	var reports = report{}

	err = db.QueryRow(`
	select merchant_name , outlet_name, sum(bill_total), date_create from ( 
		select merchant_name, outlet_name, bill_total, DATE_FORMAT(t.created_at,"%Y-%m-%d") date_create from Merchants m 
		left join Outlets o on m.id = o.merchant_id 
		left join Transactions t on t.outlet_id = o.id
		) a
		where date_create >= '2021-11-01' and date_create <= '2021-11-30'
		group by date_create,outlet_name, merchant_name 
		order by date_create asc
	`).Scan(&reports.Merchant_name,
		&reports.Outlet_name,
		&reports.Omzet,
		&reports.Date_create)

	return reports
}

func ReadData() (res []string) {
	// db, err := sql.Open("mysql", "user1@/my_db")
	connect_db()

	defer db.Close()

	rows, err := db.Query(
		`select Merchant_name , Outlet_name, sum(bill_total) omzet, date_create from ( 
		select merchant_name, outlet_name, bill_total, DATE_FORMAT(t.created_at,'%Y-%m-%d') date_create from Merchants m 
		left join Outlets o on m.id = o.merchant_id 
		left join Transactions t on t.outlet_id = o.id
		left join Users u on u.id = m.user_id
		where u.id =2
		) a
		where date_create >= '2021-11-01' and date_create <= '2021-11-30' 
		group by date_create,outlet_name, merchant_name 
		order by date_create asc
	`)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rows.Close()
	var reports = report{}
	for rows.Next() {
		err := rows.Scan(&reports.Merchant_name, &reports.Outlet_name, &reports.Omzet, &reports.Date_create)
		if err != nil {
			fmt.Println(err)
			return
		}
		res = append(res, reports.Merchant_name, reports.Outlet_name, reports.Omzet, reports.Date_create)
	}
	return
}

/*
	find data Users
*/
func QueryUser(username string) user {
	var users = user{}

	err = db.QueryRow(`
		SELECT id, 
		user_name, 
		password 
		FROM Users WHERE user_name=?
		`, username).
		Scan(
			&users.ID,
			&users.Username,
			&users.Password,
		)
	return users
}

/*
	Halaman utama web setelah login
*/
func home(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	if len(session.GetString("username")) == 0 {
		http.Redirect(w, r, "/login", 301)
	}

	var data = map[string]string{
		"username": session.GetString("username"),
		"message":  "Welcome to the Go Majoo !",
	}
	var t, err = template.ParseFiles("views/home.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, data)
	return

}

/*
 	Fungsi checkErr  untuk validate when login
	Response Code 301 = Pengalihan Permanent
*/
func checkErr(w http.ResponseWriter, r *http.Request, err error) bool {
	if err != nil {
		fmt.Println(r.Host + r.URL.Path)
		http.Redirect(w, r, r.Host+r.URL.Path, 301)
		return false
	}
	return true
}

/*
	untuk logout
	Response Code 302 = pengalihan URL
*/
func logout(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	session.Clear()
	sessions.Destroy(w, r)
	http.Redirect(w, r, "/", 302)
}

func main() {
	connect_db()
	routes()

	if err == nil {
		fmt.Println("Server running at:http://localhost:3500")
	}
	defer db.Close()
	http.ListenAndServe(":3500", nil)
}
