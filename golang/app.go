package main

import (
	crand "crypto/rand"
	"database/sql"
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

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
    session := getSession(r)
    value, ok := session.Values[key]

    if !ok || value == nil {
        return ""
    } else {
        delete(session.Values, key) // 플래시 메시지는 한 번 읽으면 삭제
        session.Save(r, w)          // 세션 변경사항 저장
        return value.(string)
    }
}


func getSessionUser(r *http.Request) User {
    session := getSession(r)
    uid, ok := session.Values["user_id"]
    if !ok || uid == nil {
        return User{}
    }

    u := User{}
    var err error // err 변수를 함수 시작 부분에 선언하여 스코프 문제 방지

    cacheKey := fmt.Sprintf("user:%v", uid)
    item, cacheErr := memcacheClient.Get(cacheKey)

    if cacheErr == nil {
        // json.Unmarshal의 에러를 직접 'err' 변수에 할당
        err = json.Unmarshal(item.Value, &u)
        if err == nil { // 언마샬 성공 시
            return u
        }
        // 언마샬 실패 (캐시 깨짐) 시 로그 출력
        log.Printf("Broken cache for user:%v: %v. Fetching from DB.", uid, err)
    } else if cacheErr != memcache.ErrCacheMiss {
        // Memcached 통신 오류 등, DB에서 조회하기 전에 로그 출력
        log.Printf("Error getting user from memcache for user %v: %v. Fetching from DB.", uid, cacheErr)
        // cacheErr를 err에 할당하여 이후 흐름에서 참조 가능하게 함 (선택 사항이지만 일관성을 위해)
        err = cacheErr
    }
    // 캐시 미스 또는 캐시 오류 발생 시 DB에서 조회

    // DB에서 가져오기
    dbErr := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
    if dbErr != nil {
        log.Printf("Failed to get user %v from DB: %v", uid, dbErr)
        return User{}
    }

    // 캐시에 저장
    if userJSON, marshalErr := json.Marshal(u); marshalErr == nil {
        memcacheClient.Set(&memcache.Item{
            Key:        cacheKey,
            Value:      userJSON,
            Expiration: 300, // 5 minutes
        })
    } else {
        log.Printf("Error marshaling user %v to cache: %v", uid, marshalErr)
    }

    return u
}

// makePosts 함수 (최종 개선 버전)
func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
    var posts []Post
    var err error // err 변수를 함수 시작 부분에 선언하여 스코프 문제 방지

    if len(results) == 0 {
        return []Post{}, nil
    }

    postIDs := make([]int, 0, len(results))
    allUserIDsSet := make(map[int]struct{}) // 중복 제거를 위한 맵 (새로운 변수명)

    for _, p := range results {
        postIDs = append(postIDs, p.ID)
        allUserIDsSet[p.UserID] = struct{}{} // 게시물 작성자 ID 수집
    }

    commentCounts := make(map[int]int)
    missingPostIDsForCommentCount := []int{}

    for _, pid := range postIDs {
        cacheKey := fmt.Sprintf("comment_count:%d", pid)
        item, cacheErr := memcacheClient.Get(cacheKey)
        if cacheErr == nil {
            var count int
            if unmarshalErr := json.Unmarshal(item.Value, &count); unmarshalErr == nil {
                commentCounts[pid] = count
            } else {
                missingPostIDsForCommentCount = append(missingPostIDsForCommentCount, pid)
                log.Printf("Broken cache for comment_count:%d: %v", pid, unmarshalErr)
            }
        } else if cacheErr == memcache.ErrCacheMiss {
            missingPostIDsForCommentCount = append(missingPostIDsForCommentCount, pid)
        } else {
            missingPostIDsForCommentCount = append(missingPostIDsForCommentCount, pid)
            log.Printf("Error getting comment count from memcache for post %d: %v", pid, cacheErr)
        }
    }

    if len(missingPostIDsForCommentCount) > 0 {
        placeholders := strings.Repeat("?,", len(missingPostIDsForCommentCount))
        placeholders = placeholders[:len(placeholders)-1]

        query := fmt.Sprintf("SELECT `post_id`, COUNT(*) AS `count` FROM `comments` WHERE `post_id` IN (%s) GROUP BY `post_id`", placeholders)

        args := make([]interface{}, len(missingPostIDsForCommentCount))
        for i, v := range missingPostIDsForCommentCount {
            args[i] = v
        }

        var dbCommentCounts []struct {
            PostID int `db:"post_id"`
            Count  int `db:"count"`
        }
        err = db.Select(&dbCommentCounts, query, args...) // sqlx.Select 사용
        if err != nil {
            return nil, fmt.Errorf("failed to get comment counts from DB: %w", err)
        }

        for _, c := range dbCommentCounts {
            commentCounts[c.PostID] = c.Count
            if countJSON, marshalErr := json.Marshal(c.Count); marshalErr == nil {
                memcacheClient.Set(&memcache.Item{
                    Key:        fmt.Sprintf("comment_count:%d", c.PostID),
                    Value:      countJSON,
                    Expiration: 180, // 3분
                })
            } else {
                log.Printf("Error marshaling comment count for post %d: %v", c.PostID, marshalErr)
            }
        }
    }

    // 3. 모든 필요한 사용자 정보를 usersMap에 채워 넣기 (게시물 작성자 + 댓글 작성자)
    // 이 단계에서 `allUserIDsSet`에 있는 사용자들을 먼저 가져옵니다.
    // 댓글 작성자 ID는 아래 루프에서 추가로 수집한 후, 다시 `fetchUsersBatch`를 호출하여 채웁니다.
    usersMap := make(map[int]User)
    
    // 초기 사용자 ID들을 슬라이스로 변환
    initialUserIDs := []int{}
    for uid := range allUserIDsSet {
        initialUserIDs = append(initialUserIDs, uid)
    }

    if len(initialUserIDs) > 0 {
        initialFetchedUsers, fetchErr := fetchUsersBatch(initialUserIDs)
        if fetchErr != nil {
            return nil, fmt.Errorf("failed to fetch initial users batch: %w", fetchErr)
        }
        for _, u := range initialFetchedUsers {
            usersMap[u.ID] = u
        }
    }

    // 4. 각 게시물에 대한 정보 (댓글 수, 댓글, 사용자 정보)를 조합하여 Post 객체 생성
    for _, p := range results {
        p.CommentCount = commentCounts[p.ID]

        var comments []Comment
        fetchedCommentsFromDB := false

        commentsCacheKey := fmt.Sprintf("comments:%d:%t", p.ID, allComments)
        item, cacheErr := memcacheClient.Get(commentsCacheKey)

        if cacheErr == nil {
            if unmarshalErr := json.Unmarshal(item.Value, &comments); unmarshalErr != nil {
                log.Printf("Broken cache for comments:%d:%t: %v. Fetching from DB.", p.ID, allComments, unmarshalErr)
                fetchedCommentsFromDB = true
            }
        } else if cacheErr == memcache.ErrCacheMiss {
            fetchedCommentsFromDB = true
        } else {
            log.Printf("Error getting comments from memcache for post %d: %v. Fetching from DB.", p.ID, cacheErr)
            fetchedCommentsFromDB = true
        }

        if fetchedCommentsFromDB {
            query := "SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC"
            if !allComments {
                query += " LIMIT 3"
            }
            err = db.Select(&comments, query, p.ID)
            if err != nil {
                return nil, fmt.Errorf("failed to get comments for post %d from DB: %w", p.ID, err)
            }

            // DB에서 가져온 댓글들을 캐시에 저장
            if commentsJSON, marshalErr := json.Marshal(comments); marshalErr == nil {
                memcacheClient.Set(&memcache.Item{
                    Key:        commentsCacheKey,
                    Value:      commentsJSON,
                    Expiration: 180, // 3분
                })
            } else {
                log.Printf("Error marshaling comments for post %d to cache: %v", p.ID, marshalErr)
            }
        }
        
        // 댓글 작성자 ID를 추가로 수집하여 usersMap을 업데이트할 준비
        newCommentUserIDsToFetch := []int{}
        for _, c := range comments {
            if _, found := usersMap[c.UserID]; !found { // usersMap에 없는 사용자만
                allUserIDsSet[c.UserID] = struct{}{} // 전체 사용자 ID 집합에도 추가
                newCommentUserIDsToFetch = append(newCommentUserIDsToFetch, c.UserID)
            }
        }
        
        // 새로운 댓글 작성자 ID가 있다면 usersMap에 추가로 채워넣음
        if len(newCommentUserIDsToFetch) > 0 {
            fetchedNewCommentUsers, fetchErr := fetchUsersBatch(newCommentUserIDsToFetch)
            if fetchErr != nil {
                return nil, fmt.Errorf("failed to fetch new comment users batch: %w", fetchErr)
            }
            for _, u := range fetchedNewCommentUsers {
                usersMap[u.ID] = u
            }
        }

        // 댓글에 사용자 정보 할당
        for i := 0; i < len(comments); i++ {
            comments[i].User = usersMap[comments[i].UserID]
        }
        // reverse
        for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
            comments[i], comments[j] = comments[j], comments[i]
        }
        p.Comments = comments

        // 게시물 작성자 정보 할당
        p.User = usersMap[p.UserID]
        p.CSRFToken = csrfToken

        if p.User.DelFlg == 0 {
            posts = append(posts, p)
        }
        if len(posts) >= postsPerPage {
            break
        }
    }

    return posts, nil
}

func fetchUsersBatch(userIDs []int) ([]User, error) {
    if len(userIDs) == 0 {
        return []User{}, nil
    }

    usersMap := make(map[int]User) // 최종적으로 반환될 사용자 맵
    missingUserIDs := []int{} // DB에서 가져와야 할 ID

    for _, uid := range userIDs {
        cacheKey := fmt.Sprintf("user:%d", uid)
        item, cacheErr := memcacheClient.Get(cacheKey)
        if cacheErr == nil {
            var cachedUser User
            if unmarshalErr := json.Unmarshal(item.Value, &cachedUser); unmarshalErr == nil {
                usersMap[uid] = cachedUser
            } else {
                missingUserIDs = append(missingUserIDs, uid)
                log.Printf("Broken cache for user:%d: %v", uid, unmarshalErr)
            }
        } else if cacheErr == memcache.ErrCacheMiss {
            missingUserIDs = append(missingUserIDs, uid)
        } else {
            missingUserIDs = append(missingUserIDs, uid)
            log.Printf("Error getting user from memcache for user %d: %v", uid, cacheErr)
        }
    }

    if len(missingUserIDs) > 0 {
        placeholders := strings.Repeat("?,", len(missingUserIDs))
        placeholders = placeholders[:len(placeholders)-1]

        query := fmt.Sprintf("SELECT * FROM `users` WHERE `id` IN (%s)", placeholders)

        args := make([]interface{}, len(missingUserIDs))
        for i, v := range missingUserIDs {
            args[i] = v
        }

        var dbUsers []User
        err := db.Select(&dbUsers, query, args...) // err에 할당
        if err != nil {
            return nil, fmt.Errorf("failed to get users from DB: %w", err)
        }

        for _, u := range dbUsers {
            usersMap[u.ID] = u
            if userJSON, marshalErr := json.Marshal(u); marshalErr == nil {
                memcacheClient.Set(&memcache.Item{
                    Key:        fmt.Sprintf("user:%d", u.ID),
                    Value:      userJSON,
                    Expiration: 300, // 5분
                })
            } else {
                log.Printf("Error marshaling user %d to cache: %v", u.ID, marshalErr)
            }
        }
    }

    resultUsers := make([]User, 0, len(usersMap))
    for _, u := range usersMap {
        resultUsers = append(resultUsers, u)
    }
    return resultUsers, nil
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
    var err error // err 변수 선언

    err = db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
    if err != nil {
        if err == sql.ErrNoRows {
            w.WriteHeader(http.StatusNotFound)
            return
        }
        log.Print(err)
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    // 사용자 정보 캐싱 (조회 후 캐시 누락 시). fetchUsersBatch와 유사한 로직으로 통합 가능하지만,
    // 여기서는 단일 조회이므로 직접 처리합니다.
    cacheKey := fmt.Sprintf("user:%v", user.ID)
    if userJSON, marshalErr := json.Marshal(user); marshalErr == nil {
        memcacheClient.Set(&memcache.Item{
            Key:        cacheKey,
            Value:      userJSON,
            Expiration: 300, // 5분
        })
    } else {
        log.Printf("Error marshaling user %v to cache in getAccountName: %v", user.ID, marshalErr)
    }

    // --- 통계 정보 한 번에 가져오기 최적화 (JOIN 기반) ---
    // MySQL 옵티마이저가 JOIN을 잘 활용할 수 있도록 COUNT(CASE WHEN ...)과 LEFT JOIN을 결합
    statsQuery := `
        SELECT
            COUNT(DISTINCT p.id) AS post_count,
            COUNT(DISTINCT c_user.id) AS comment_count,
            COUNT(DISTINCT c_post.id) AS commented_count
        FROM
            users u
        LEFT JOIN
            posts p ON u.id = p.user_id
        LEFT JOIN
            comments c_user ON u.id = c_user.user_id -- 사용자가 직접 단 댓글
        LEFT JOIN
            comments c_post ON p.id = c_post.post_id -- 사용자의 게시물에 달린 댓글
        WHERE
            u.id = ? AND u.del_flg = 0;
    `
    // 이 쿼리는 유저 ID에 대한 인덱스가 users.id, posts.user_id, comments.user_id, comments.post_id 에 모두 잘 걸려있을 때 효율적입니다.
    // (보통 외래 키(FK)가 걸려있는 컬럼에는 자동으로 인덱스가 생성되거나, 직접 걸어주는 것이 좋습니다.)

    stats := struct {
        PostCount      int `db:"post_count"`
        CommentCount   int `db:"comment_count"`
        CommentedCount int `db:"commented_count"`
    }{}

    err = db.Get(&stats, statsQuery, user.ID) // err에 할당
    if err != nil {
        log.Printf("Failed to get user stats for %s: %v", accountName, err)
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    results := []Post{}
    err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC", user.ID) // err에 할당
    if err != nil {
        log.Printf("Failed to get posts for user %s: %v", accountName, err)
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    posts, err := makePosts(results, getCSRFToken(r), false) // err에 할당
    if err != nil {
        log.Printf("Failed to make posts for user %s: %v", accountName, err)
        w.WriteHeader(http.StatusInternalServerError)
        return
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
    }{posts, user, stats.PostCount, stats.CommentCount, stats.CommentedCount, me})
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
	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC", t.Format(ISO8601Format))
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
    pid, err := strconv.Atoi(pidStr) // err 변수 선언
    if err != nil {
        w.WriteHeader(http.StatusNotFound)
        return
    }

    post := Post{}
    
    // ext 변수를 먼저 선언하여 스코프를 확장
    ext := r.PathValue("ext") 
    
    fetchedFromDB := false // DB에서 가져왔는지 여부 플래그

    cacheKey := fmt.Sprintf("post_data:%d", pid)
    item, cacheErr := memcacheClient.Get(cacheKey)

    if cacheErr == nil {
        if unmarshalErr := json.Unmarshal(item.Value, &post); unmarshalErr != nil {
            log.Printf("Broken cache for post_data:%d: %v. Fetching from DB.", pid, unmarshalErr)
            fetchedFromDB = true
        }
    } else if cacheErr == memcache.ErrCacheMiss {
        fetchedFromDB = true
    } else {
        log.Printf("Error getting post_data from memcache for post %d: %v. Fetching from DB.", pid, cacheErr)
        fetchedFromDB = true
    }

    if fetchedFromDB {
        err = db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid) // err에 할당
        if err != nil {
            if err == sql.ErrNoRows {
                w.WriteHeader(http.StatusNotFound)
                return
            }
            log.Printf("Failed to get post %d from DB: %v", pid, err)
            w.WriteHeader(http.StatusInternalServerError)
            return
        }

        if postJSON, marshalErr := json.Marshal(post); marshalErr == nil {
            memcacheClient.Set(&memcache.Item{
                Key:        cacheKey,
                Value:      postJSON,
                Expiration: 600, // 10分
            })
        } else {
            log.Printf("Error marshaling post %d to cache: %v", pid, marshalErr)
        }
    }

    if (ext == "jpg" && post.Mime == "image/jpeg") ||
        (ext == "png" && post.Mime == "image/png") ||
        (ext == "gif" && post.Mime == "image/gif") {
        w.Header().Set("Content-Type", post.Mime)
        _, writeErr := w.Write(post.Imgdata)
        if writeErr != nil {
            log.Printf("Error writing image data for post %d: %v", pid, writeErr)
            http.Error(w, "Failed to write image data", http.StatusInternalServerError)
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
        log.Printf("post_id는整数のみです: %v", err)
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    commentBody := r.FormValue("comment")
    if commentBody == "" {
        session := getSession(r)
        session.Values["notice"] = "コメントは必須です"
        session.Save(r, w)
        http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
        return
    }

    query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
    _, err = db.Exec(query, postID, me.ID, commentBody)
    if err != nil {
        log.Printf("Failed to insert comment: %v", err)
        http.Error(w, "Failed to post comment", http.StatusInternalServerError)
        return
    }

    // --- 캐시 무효화 로직 ---
    // 댓글이 추가되었으므로 해당 게시물의 댓글 수 캐시를 무효화합니다.
    memcacheClient.Delete(fmt.Sprintf("comment_count:%d", postID))
    // 또한, 해당 게시물의 댓글 목록 캐시 (allComments: true/false 모두)도 무효화합니다.
    memcacheClient.Delete(fmt.Sprintf("comments:%d:true", postID))
    memcacheClient.Delete(fmt.Sprintf("comments:%d:false", postID))
    // --- 캐시 무효화 로직 끝 ---

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
