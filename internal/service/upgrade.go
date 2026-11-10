package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const maxBinaryBytes = 64 << 20

var releaseTag = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)

// Release — последний стабильный релиз на GitHub.
type Release struct {
	Repo string
	Tag  string
}

func (r Release) assetURL(name string) string {
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", r.Repo, r.Tag, name)
}

// AssetName — имя бинарника релиза для текущей архитектуры.
func AssetName() string {
	return "rkn-guard-linux-" + runtime.GOARCH
}

func httpGet(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rkn-guard")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: ответ больше %d байт", url, limit)
	}
	return data, nil
}

// LatestRelease спрашивает у GitHub последний стабильный релиз.
func LatestRelease(ctx context.Context, repo string) (Release, error) {
	data, err := httpGet(ctx, "https://api.github.com/repos/"+repo+"/releases/latest", 1<<20)
	if err != nil && strings.HasSuffix(err.Error(), "HTTP 404") {
		return Release{}, fmt.Errorf("в github.com/%s ещё нет опубликованных релизов", repo)
	}
	if err != nil {
		return Release{}, fmt.Errorf("не удалось узнать последний релиз: %w", err)
	}
	var payload struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(data, &payload); err != nil || !releaseTag.MatchString(payload.Tag) {
		return Release{}, fmt.Errorf("GitHub вернул неожиданный ответ о релизе")
	}
	return Release{Repo: repo, Tag: payload.Tag}, nil
}

// expectedChecksum ищет хеш файла в checksums.txt формата sha256sum.
func expectedChecksum(checksums []byte, name string) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(checksums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name && len(fields[0]) == 64 {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("в checksums.txt нет %s", name)
}

// InstallRelease скачивает бинарник, сверяет sha256 и атомарно заменяет target.
func InstallRelease(ctx context.Context, release Release, target string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	name := AssetName()
	checksums, err := httpGet(ctx, release.assetURL("checksums.txt"), 1<<20)
	if err != nil {
		return err
	}
	want, err := expectedChecksum(checksums, name)
	if err != nil {
		return err
	}
	binary, err := httpGet(ctx, release.assetURL(name), maxBinaryBytes)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(binary)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("контрольная сумма %s не совпала: ожидалась %s, получена %s", name, want, got)
	}
	return ReplaceBinary(binary, target)
}

// ReplaceBinary кладёт новый бинарник рядом с target, проверяет запуск и переименовывает.
func ReplaceBinary(binary []byte, target string) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".rkn-guard-new-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if out, err := exec.Command(tmp.Name(), "version").CombinedOutput(); err != nil {
		return fmt.Errorf("новый бинарник не запускается: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return os.Rename(tmp.Name(), target)
}

// CopySelf устанавливает текущий бинарник в target, если запущен не оттуда.
func CopySelf(target string) (bool, error) {
	self, err := os.Executable()
	if err != nil {
		return false, err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	if current, err := filepath.EvalSymlinks(target); err == nil && current == self {
		return false, nil
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return false, err
	}
	return true, ReplaceBinary(data, target)
}
