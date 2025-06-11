package main

import (
	"crypto/rand"
	"crypto/sha512"
	"database/sql"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
)

var (
	db        *sqlx.DB
	store     *gsm.MemcacheStore
	templates *template.Template // ★★★ 템플릿 캐싱을 위한 전역 변수
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient := memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// ★★★ 세션에 User 구조체를 저장하기 위해 gob에 등록
	gob.Register(User{})

	// ★★★ 템플릿 함수맵 등록
	fmap := template.FuncMap{
		"imageURL": imageURL,
	}
	// ★★★ 애플리케이션 시작 시 모든 템플릿을 미리 파싱하여 캐싱
	templates = template.Must(template.New("layout.html").Funcs(fmap).ParseGlob(getTemplPath("*.html")))
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

// ★★★ [개선] 외부 프로세스 호출 제거. Go 네이티브 crypto 라이브러리 사용
func digest(src string) string {
	hasher := sha512.New()
	hasher.Write([]byte(src))
	return hex.EncodeToString(hasher.Sum(nil))
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")
	return session
}

// ★★★ [개선] DB 조회 없이 세션에서 직접 사용자 정보 반환
func getSessionUser(r *http.Request) User {
	session := getSession(r)
	val := session.Values["user"]
	if val == nil {
		return User{}
	}
	u, ok := val.(User)
	if !ok {
		return User{}
	}
	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

// ★★★ [개선] N+1 쿼리 문제를 해결한 새로운 makePosts 함수
func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	if len(results) == 0 {
		return []Post{}, nil
	}

	// 1. 필요한 ID들을 수집
	postIDs := make([]int, 0, len(results))
	userIDs := make(map[int]struct{})
	for _, p := range results {
		postIDs = append(postIDs, p.ID)
		userIDs[p.UserID] = struct{}{}
	}

	// 2. IN 절을 사용해 댓글들을 한 번에 조회
	query, args, err := sqlx.In("SELECT * FROM `comments` WHERE `post_id` IN (?) ORDER BY `created_at` ASC", postIDs)
	if err != nil {
		return nil, err
	}
	var comments []Comment
	err = db.Select(&comments, query, args...)
	if err != nil {
		return nil, err
	}

	// 댓글 작성자 ID 수집
	for _, c := range comments {
		userIDs[c.UserID] = struct{}{}
	}

	// 3. IN 절을 사용해 필요한 모든 사용자 정보를 한 번에 조회
	userIDSlice := make([]int, 0, len(userIDs))
	for id := range userIDs {
		userIDSlice = append(userIDSlice, id)
	}
	userQuery, userArgs, err := sqlx.In("SELECT * FROM `users` WHERE `id` IN (?)", userIDSlice)
	if err != nil {
		return nil, err
	}
	var users []User
	err = db.Select(&users, userQuery, userArgs...)
	if err != nil {
		return nil, err
	}

	// 4. 빠른 조회를 위해 사용자 정보와 댓글을 맵으로 변환
	userMap := make(map[int]User, len(users))
	for _, u := range users {
		userMap[u.ID] = u
	}

	commentMap := make(map[int][]Comment, len(comments))
	for _, c := range comments {
		if user, ok := userMap[c.UserID]; ok {
			c.User = user
			commentMap[c.PostID] = append(commentMap[c.PostID], c)
		}
	}

	// 5. 최종 데이터 조합
	posts := make([]Post, 0, len(results))
	for _, p := range results {
		// 사용자 정보와 댓글 정보 할당
		if user, ok := userMap[p.UserID]; ok && user.DelFlg == 0 {
			p.User = user
			p.Comments = commentMap[p.ID]
			p.CommentCount = len(p.Comments)
			p.CSRFToken = csrfToken

			// allComments가 false일 때 최근 3개 댓글만 표시
			if !allComments && len(p.Comments) > 3 {
				p.Comments = p.Comments[len(p.Comments)-3:]
			}
			posts = append(posts, p)
		}

		if len(posts) >= postsPerPage {
			break
		}
	}

	return posts, nil
}


func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
    k := make([]byte, b)
    if _, err := rand.Read(k); err != nil { // Use crypto/rand.Read()
        panic(err)
    }
    return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// ★★★ [개선] 캐싱된 템플릿 사용
	templates.ExecuteTemplate(w, "login.html", struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		// ★★★ [개선] 세션에 User 객체 저장
		session.Values["user"] = *u
		session.Values["user_id"] = u.ID // 이전 버전 호환성을 위해 유지 가능
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "계정명 또는 비밀번호가 틀렸습니다"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// ★★★ [개선] 캐싱된 템플릿 사용
	templates.ExecuteTemplate(w, "register.html", struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "계정명은 3자 이상, 비밀번호는 6자 이상이어야 합니다"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	var exists int
	err := db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)
	if err != nil && err != sql.ErrNoRows {
		log.Print(err)
		http.Error(w, "DB Error", http.StatusInternalServerError)
		return
	}

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "이미 사용중인 계정명입니다"
		session.Save(r, w)
		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	// ★★★ [개선] 세션에 저장할 사용자 정보 조회 및 저장
	var u User
	err = db.Get(&u, "SELECT * FROM users WHERE id = ?", uid)
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	session.Values["user"] = u
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user")
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []Post{}
	err := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	// ★★★ [개선] 캐싱된 템플릿 사용
	templates.ExecuteTemplate(w, "index.html", struct {
		Posts     []Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})
}

func getAccountName(w http.ResponseWriter, r *http.Request) {
    accountName := chi.URLParam(r, "accountName") // chi v5
    var user User

    err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
    if err == sql.ErrNoRows {
        w.WriteHeader(http.StatusNotFound)
        return
    }
    if err != nil {
        log.Print(err)
        http.Error(w, "Not Found", http.StatusNotFound)
        return
    }

    results := []Post{}
    err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC", user.ID)
    if err != nil {
        log.Print(err)
        return
    }

    posts, err := makePosts(results, getCSRFToken(r), false)
    if err != nil {
        log.Print(err)
        return
    }

    // ★★★ [개선] 쿼리 효율화
    var postCount int
    err = db.Get(&postCount, "SELECT COUNT(*) FROM `posts` WHERE `user_id` = ?", user.ID)
    if err != nil {
        log.Print(err)
        return
    }

    var commentCount int
    err = db.Get(&commentCount, "SELECT COUNT(*) FROM `comments` WHERE `user_id` = ?", user.ID)
    if err != nil {
        log.Print(err)
        return
    }

    var commentedCount int
    err = db.Get(&commentedCount, "SELECT COUNT(*) FROM `comments` WHERE `post_id` IN (SELECT `id` FROM `posts` WHERE `user_id` = ?)", user.ID)
    if err != nil && err != sql.ErrNoRows {
        log.Print(err)
        return
    }

    me := getSessionUser(r)

    // ★★★ [개선] 캐싱된 템플릿 사용
    templates.ExecuteTemplate(w, "user.html", struct {
        Posts          []Post
        User           User
        PostCount      int
        CommentCount   int
        CommentedCount int
        Me             User
    }{posts, user, postCount, commentCount, commentedCount, me})
}

// ... 이하 다른 핸들러 함수들도 유사하게 캐싱된 템플릿을 사용하도록 수정합니다 ...
// (postIndex, getImage, postComment, getAdminBanned, postAdminBanned 등은 템플릿을 직접 사용하지 않으므로 변경 불필요)
// getPosts, getPostsID, getAdminBanned는 ExecuteTemplate을 사용하도록 수정 필요

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC", t.Format(time.RFC3339Nano))
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// ★★★ [개선] 캐싱된 템플릿 사용
	templates.ExecuteTemplate(w, "posts.html", posts)
}

func getPostsID(w http.ResponseWriter, r *http.Request) {
    pidStr := chi.URLParam(r, "id") // chi v5
    pid, err := strconv.Atoi(pidStr)
    if err != nil {
        w.WriteHeader(http.StatusNotFound)
        return
    }

    var p Post
    err = db.Get(&p, "SELECT * FROM `posts` WHERE `id` = ?", pid)
    if err == sql.ErrNoRows {
        w.WriteHeader(http.StatusNotFound)
        return
    }
    if err != nil {
        log.Print(err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    posts, err := makePosts([]Post{p}, getCSRFToken(r), true)
    if err != nil {
        log.Print(err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    if len(posts) == 0 {
        w.WriteHeader(http.StatusNotFound)
        return
    }

    me := getSessionUser(r)

    // ★★★ [개선] 캐싱된 템플릿 사용
    templates.ExecuteTemplate(w, "post_id.html", struct {
        Post Post
        Me   User
    }{posts[0], me})
}
func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		filedata,
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := Post{}
	err = db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	ext := r.PathValue("ext")

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		w.Header().Set("Content-Type", post.Mime)
		_, err := w.Write(post.Imgdata)
		if err != nil {
			log.Print(err)
			return
		}
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	_, err = db.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) || me.Authority == 0 {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	var users []User
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	// ★★★ [개선] 캐싱된 템플릿 사용
	templates.ExecuteTemplate(w, "banned.html", struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

// ... 라우터 및 main 함수 ...
func main() {
    host := os.Getenv("ISUCONP_DB_HOST")
    if host == "" {
        host = "localhost"
    }
    port := os.Getenv("ISUCONP_DB_PORT")
    if port == "" {
        port = "3306"
    }
    _, err := strconv.Atoi(port)
    if err != nil {
        log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
    }
    user := os.Getenv("ISUCONP_DB_USER")
    if user == "" {
        user = "root"
    }
    password := os.Getenv("ISUCONP_DB_PASSWORD")
    dbname := os.Getenv("ISUCONP_DB_NAME")
    if dbname == "" {
        dbname = "isuconp"
    }

    dsn := fmt.Sprintf(
        "%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local",
        user,
        password,
        host,
        port,
        dbname,
    )

    db, err = sqlx.Open("mysql", dsn)
    if err != nil {
        log.Fatalf("Failed to connect to DB: %s.", err.Error())
    }
    defer db.Close()
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

    r := chi.NewRouter()

    r.Get("/initialize", getInitialize)
    r.Get("/login", getLogin)
    r.Post("/login", postLogin)
    r.Get("/register", getRegister)
    r.Post("/register", postRegister)
    r.Get("/logout", getLogout)
    r.Get("/", getIndex)
    r.Get("/posts", getPosts)
    r.Get("/posts/{id}", getPostsID)
    r.Post("/", postIndex)
    r.Get("/image/{id}.{ext}", getImage)
    r.Post("/comment", postComment)
    r.Get("/admin/banned", getAdminBanned)
    r.Post("/admin/banned", postAdminBanned)
    r.Get(`/@{accountName:[a-zA-Z0-9_]+}`, getAccountName) // 사용자 이름 규칙에 맞춰 정규식 수정
    r.Handle("/css/*", http.StripPrefix("/css/", http.FileServer(http.Dir("../public/css"))))
    r.Handle("/js/*", http.StripPrefix("/js/", http.FileServer(http.Dir("../public/js"))))


    log.Fatal(http.ListenAndServe(":8080", r))
}