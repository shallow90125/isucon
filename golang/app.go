package main

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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
	db    *sqlx.DB
	store *gsm.MemcacheStore
	memcacheClient *memcache.Client
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
	memcacheClient = memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
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
	// DB 초기화 시 모든 캐시를 비워주는 것이 좋습니다.
	memcacheClient.FlushAll()
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

// 今回のGo実装では言語側のエスケープの仕組みが使えないのでOSコマンドインジェクション対策できない
// 取り急ぎPHPのescapeshellarg関数を参考に自前で実装
// cf: http://jp2.php.net/manual/ja/function.escapeshellarg.php
func escapeshellarg(arg string) string {
	return "'" + strings.Replace(arg, "'", "'\\''", -1) + "'"
}

func digest(src string) string {
	// opensslのバージョンによっては (stdin)= というのがつくので取る
	out, err := exec.Command("/bin/bash", "-c", `printf "%s" `+escapeshellarg(src)+` | openssl dgst -sha512 | sed 's/^.*= //'`).Output()
	if err != nil {
		log.Print(err)
		return ""
	}

	return strings.TrimSuffix(string(out), "\n")
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

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	u := User{}

	// キャッシュから取得を試行
	cacheKey := fmt.Sprintf("user:%v", uid)
	item, err := memcacheClient.Get(cacheKey)
	if err == nil {
		// キャッシュヒット
		if err := json.Unmarshal(item.Value, &u); err == nil {
			return u
		}
	}

	// キャッシュミス、DBから取得
	err = db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	if err != nil {
		return User{}
	}

	// キャッシュに保存
	if userJSON, err := json.Marshal(u); err == nil {
		memcacheClient.Set(&memcache.Item{
			Key:        cacheKey,
			Value:      userJSON,
			Expiration: 300, // 5分
		})
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

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	var posts []Post

	// 모든 관련 user_id와 post_id를 수집합니다.
	userIDSet := make(map[int]struct{})
	postIDSet := make(map[int]struct{})
	for _, p := range results {
		userIDSet[p.UserID] = struct{}{}
		postIDSet[p.ID] = struct{}{}
	}

	// 댓글 사용자 ID도 수집해야 합니다.
	var allCommentsData []Comment
	if len(postIDSet) > 0 {
		postIDs := make([]interface{}, 0, len(postIDSet))
		for id := range postIDSet {
			postIDs = append(postIDs, id)
		}
		placeholder := strings.Join(strings.Split(strings.Repeat("?", len(postIDs)), ""), ", ")

		// 모든 관련 댓글을 가져옵니다 (배치 조회).
		commentsQuery := "SELECT * FROM `comments` WHERE `post_id` IN (" + placeholder + ") ORDER BY `created_at` DESC"
		err := db.Select(&allCommentsData, commentsQuery, postIDs...)
		if err != nil {
			return nil, err
		}

		for _, c := range allCommentsData {
			userIDSet[c.UserID] = struct{}{}
		}
	}

	// 모든 사용자 정보를 배치로 가져옵니다.
	userMap := make(map[int]User)
	if len(userIDSet) > 0 {
		userIDs := make([]interface{}, 0, len(userIDSet))
		for id := range userIDSet {
			userIDs = append(userIDs, id)
		}
		
		// Memcache에서 사용자 정보를 배치로 가져오기 시도
		userCacheKeys := make([]string, 0, len(userIDs))
		for _, uid := range userIDs {
			userCacheKeys = append(userCacheKeys, fmt.Sprintf("user:%v", uid))
		}
		cachedItems, err := memcacheClient.GetMulti(userCacheKeys)
		if err != nil && err != memcache.ErrCacheMiss {
			log.Printf("Error getting multi user cache: %v", err)
		}

		dbUserIDs := make([]interface{}, 0)
		for _, uid := range userIDs {
			uIDInt := uid.(int)
			cacheKey := fmt.Sprintf("user:%d", uIDInt)
			if item, ok := cachedItems[cacheKey]; ok {
				var u User
				if err := json.Unmarshal(item.Value, &u); err == nil {
					userMap[u.ID] = u
				} else {
					log.Printf("Error unmarshaling cached user %d: %v", uIDInt, err)
					dbUserIDs = append(dbUserIDs, uid) // 캐시 손상 시 DB에서 다시 가져오기
				}
			} else {
				dbUserIDs = append(dbUserIDs, uid)
			}
		}

		if len(dbUserIDs) > 0 {
			dbPlaceholder := strings.Join(strings.Split(strings.Repeat("?", len(dbUserIDs)), ""), ", ")
			var users []User
			err = db.Select(&users, "SELECT * FROM `users` WHERE `id` IN ("+dbPlaceholder+")", dbUserIDs...)
			if err != nil {
				return nil, err
			}
			for _, u := range users {
				userMap[u.ID] = u
				// DB에서 가져온 사용자 정보를 캐시에 저장
				if userJSON, err := json.Marshal(u); err == nil {
					memcacheClient.Set(&memcache.Item{
						Key:        fmt.Sprintf("user:%d", u.ID),
						Value:      userJSON,
						Expiration: 300, // 5분
					})
				}
			}
		}
	}

	// 댓글을 postID별로 그룹화하고 사용자 정보를 연결합니다.
	commentsByPostID := make(map[int][]Comment)
	for _, c := range allCommentsData {
		if u, ok := userMap[c.UserID]; ok {
			c.User = u
		} else {
			c.User = User{} // 사용자 정보가 없는 경우 (예: 삭제된 사용자)
		}
		commentsByPostID[c.PostID] = append(commentsByPostID[c.PostID], c)
	}

	// 모든 comment_count를 배치로 가져옵니다.
	commentCounts := make(map[int]int)
	if len(postIDSet) > 0 {
		postIDs := make([]interface{}, 0, len(postIDSet))
		for id := range postIDSet {
			postIDs = append(postIDs, id)
		}
		placeholder := strings.Join(strings.Split(strings.Repeat("?", len(postIDs)), ""), ", ")

		// 캐시에서 comment count를 배치로 가져오기 시도
		countCacheKeys := make([]string, 0, len(postIDs))
		for _, pid := range postIDs {
			countCacheKeys = append(countCacheKeys, fmt.Sprintf("comment_count:%v", pid))
		}
		cachedCounts, err := memcacheClient.GetMulti(countCacheKeys)
		if err != nil && err != memcache.ErrCacheMiss {
			log.Printf("Error getting multi comment count cache: %v", err)
		}

		dbPostIDsForCounts := make([]interface{}, 0)
		for _, pid := range postIDs {
			pIDInt := pid.(int)
			cacheKey := fmt.Sprintf("comment_count:%d", pIDInt)
			if item, ok := cachedCounts[cacheKey]; ok {
				var count int
				if err := json.Unmarshal(item.Value, &count); err == nil {
					commentCounts[pIDInt] = count
				} else {
					log.Printf("Error unmarshaling cached comment count %d: %v", pIDInt, err)
					dbPostIDsForCounts = append(dbPostIDsForCounts, pid)
				}
			} else {
				dbPostIDsForCounts = append(dbPostIDsForCounts, pid)
			}
		}

		if len(dbPostIDsForCounts) > 0 {
			dbPlaceholder := strings.Join(strings.Split(strings.Repeat("?", len(dbPostIDsForCounts)), ""), ", ")
			var dbCounts []struct {
				PostID int `db:"post_id"`
				Count  int `db:"count"`
			}
			err = db.Select(&dbCounts, "SELECT `post_id`, COUNT(*) AS `count` FROM `comments` WHERE `post_id` IN ("+dbPlaceholder+") GROUP BY `post_id`", dbPostIDsForCounts...)
			if err != nil {
				return nil, err
			}
			for _, cc := range dbCounts {
				commentCounts[cc.PostID] = cc.Count
				// DB에서 가져온 댓글 수를 캐시에 저장
				if countJSON, err := json.Marshal(cc.Count); err == nil {
					memcacheClient.Set(&memcache.Item{
						Key:        fmt.Sprintf("comment_count:%d", cc.PostID),
						Value:      countJSON,
						Expiration: 180, // 3분
					})
				}
			}
		}
	}

	for _, p := range results {
		p.CommentCount = commentCounts[p.ID] // 미리 가져온 댓글 수 할당

		// 댓글 정보를 할당하고 사용자 정보 연결
		comments := commentsByPostID[p.ID]
		var finalComments []Comment
		if !allComments && len(comments) > 3 {
			// DB에서 DESC로 가져왔으므로, slice 마지막 3개가 최신 댓글
			finalComments = comments[len(comments)-3:]
		} else {
			finalComments = comments
		}

		// reverse
		for i, j := 0, len(finalComments)-1; i < j; i, j = i+1, j-1 {
			finalComments[i], finalComments[j] = finalComments[j], finalComments[i]
		}
		p.Comments = finalComments

		// 게시글 작성자 정보 연결
		if u, ok := userMap[p.UserID]; ok {
			p.User = u
		} else {
			p.User = User{} // 게시글 작성자 정보가 없는 경우
		}

		p.CSRFToken = csrfToken

		// del_flg가 0인 사용자만 게시글에 포함 (기존 로직 유지)
		if p.User.DelFlg == 0 {
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
	if _, err := crand.Read(k); err != nil {
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

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
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
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
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
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
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

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
    me := getSessionUser(r)

    results := []Post{}

    // LIMIT 절을 추가하여 postsPerPage 만큼만 DB에서 가져옴
    err := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` ORDER BY `created_at` DESC LIMIT ?", postsPerPage)
    if err != nil {
        log.Print(err)
        return
    }

    posts, err := makePosts(results, getCSRFToken(r), false)
    if err != nil {
        log.Print(err)
        return
    }

    fmap := template.FuncMap{
        "imageURL": imageURL,
    }

    template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
        getTemplPath("layout.html"),
        getTemplPath("index.html"),
        getTemplPath("posts.html"),
        getTemplPath("post.html"),
    )).Execute(w, struct {
        Posts     []Post
        Me        User
        CSRFToken string
        Flash     string
    }{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})
}
func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := r.PathValue("accountName")
	user := User{}

	err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
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

	commentCount := 0
	err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	postIDs := []int{}
	err = db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		s := []string{}
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		err = db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...)
		if err != nil {
			log.Print(err)
			return
		}
	}

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("user.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

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
    // LIMIT 절을 추가하여 postsPerPage 만큼만 DB에서 가져옴
    err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC LIMIT ?", t.Format(ISO8601Format), postsPerPage)
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

    fmap := template.FuncMap{
        "imageURL": imageURL,
    }

    template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(
        getTemplPath("posts.html"),
        getTemplPath("post.html"),
    )).Execute(w, posts)
}
func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("post_id.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
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

    // 새 게시글 작성 시 해당 게시글의 캐시 무효화
    memcacheClient.Delete(fmt.Sprintf("post:%d", pid))
    // 전체 게시글 목록에 영향을 미칠 수 있으므로, 관련 캐시도 무효화 고려 (예: 인덱스 페이지 캐시)
    // 현재는 makePosts에서 캐싱이 개별 요소에 적용되므로 전체 무효화는 필요 없습니다.

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

	// キャッシュから投稿データを取得
	cacheKey := fmt.Sprintf("post:%d", pid)
	item, err := memcacheClient.Get(cacheKey)
	if err == nil {
		// キャッシュヒット
		if err := json.Unmarshal(item.Value, &post); err != nil {
			// キャッシュが壊れている場合はDBから取得
			err = db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
			if err != nil {
				log.Print(err)
				return
			}
		}
	} else {
		// キャッシュミス、DBから取得
		err = db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
		if err != nil {
			log.Print(err)
			return
		}

		// キャッシュに保存
		if postJSON, err := json.Marshal(post); err == nil {
			memcacheClient.Set(&memcache.Item{
				Key:        cacheKey,
				Value:      postJSON,
				Expiration: 600, // 10分
			})
		}
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

    // 새 댓글 작성 시 해당 게시글의 댓글 관련 캐시 무효화
    memcacheClient.Delete(fmt.Sprintf("comment_count:%d", postID))
    memcacheClient.Delete(fmt.Sprintf("comments:%d:true", postID))
    memcacheClient.Delete(fmt.Sprintf("comments:%d:false", postID))

    http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
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

    err := r.ParseForm()
    if err != nil {
        log.Print(err)
        return
    }

    uidsToBan := r.Form["uid[]"]
    if len(uidsToBan) > 0 {
        // Prepare placeholders for IN clause
        placeholders := make([]string, len(uidsToBan))
        args := make([]interface{}, len(uidsToBan))
        for i, uidStr := range uidsToBan {
            placeholders[i] = "?"
            uid, err := strconv.Atoi(uidStr)
            if err != nil {
                log.Printf("Invalid UID in banned list: %s, Error: %v", uidStr, err)
                continue // Skip invalid UIDs
            }
            args[i] = uid
            // 밴된 사용자의 캐시 무효화
            memcacheClient.Delete(fmt.Sprintf("user:%d", uid))
        }

        if len(args) > 0 { // Ensure there are valid UIDs to ban
            query := fmt.Sprintf("UPDATE `users` SET `del_flg` = 1 WHERE `id` IN (%s)", strings.Join(placeholders, ","))
            _, err := db.Exec(query, args...)
            if err != nil {
                log.Print(err)
                return
            }
        }
    }

    http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

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
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("../public")).ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe(":8080", r))
}
