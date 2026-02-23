package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type JobMsg struct {
	JobID  string `json:"job_id"`
	RepoID string `json:"repo_id"`
}

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	redisAddr := os.Getenv("REDIS_ADDR")
	if dbURL == "" || redisAddr == "" {
		panic("DATABASE_URL and REDIS_ADDR are required")
	}

	maxCloneMB := envInt("MAX_CLONE_MB", 350)
	timeoutMin := envInt("SCAN_TIMEOUT_MIN", 20)

	ctx := context.Background()
	db, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		panic(err)
	}

	fmt.Println("Worker online. Waiting for jobs...")

	for {
		res, err := rdb.BRPop(ctx, 0, "ssao:jobs").Result()
		if err != nil {
			fmt.Println("queue error:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if len(res) != 2 {
			continue
		}

		var msg JobMsg
		if err := json.Unmarshal([]byte(res[1]), &msg); err != nil {
			fmt.Println("bad job payload:", err)
			continue
		}

		jobCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMin)*time.Minute)
		if err := runJob(jobCtx, db, msg, maxCloneMB); err != nil {
			fmt.Println("job failed:", msg.JobID, err)
		} else {
			fmt.Println("job done:", msg.JobID)
		}
		cancel()
	}
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
