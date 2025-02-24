package caddy_storage_cf_kv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// Interface guards
var (
	_ caddy.Module           = (*Linkup)(nil)
	_ caddy.StorageConverter = (*Linkup)(nil)
	_ caddyfile.Unmarshaler  = (*Linkup)(nil)
	_ caddy.Provisioner      = (*Linkup)(nil)
	_ certmagic.Storage      = (*Linkup)(nil)
)

func init() {
	caddy.RegisterModule(Linkup{})
}

type CertificateCacheResponse struct {
	DataBase64   string `json:"data_base64"`
	Size         int    `json:"size"`
	LastModified uint64 `json:"last_modified"`
}

func (r *CertificateCacheResponse) DecodedData() ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(r.DataBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 string: %w", err)
	}

	return decoded, nil
}

type Linkup struct {
	client    *http.Client       `json:"-"`
	Logger    *zap.SugaredLogger `json:"-"`
	ctx       context.Context
	WorkerUrl string `json:"worker_url,omitempty"`
	Token     string `json:"token,omitempty"`
}

func (Linkup) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.linkup",
		New: func() caddy.Module {
			return new(Linkup)
		},
	}
}

func (s *Linkup) CertMagicStorage() (certmagic.Storage, error) {
	return s, nil
}

func (s *Linkup) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		key := d.Val()
		var value string
		if !d.Args(&value) {
			continue
		}

		switch key {
		case "worker_url":
			s.WorkerUrl = value
		case "token":
			s.Token = value
		}
	}
	return nil
}

func (s *Linkup) Provision(ctx caddy.Context) error {
	s.Logger = ctx.Logger(s).Sugar()
	s.ctx = ctx.Context

	// This adds support to the documented Caddy way to get runtime environment variables.
	// Reference: https://caddyserver.com/docs/caddyfile/concepts#environment-variables
	//
	// So, with this, it should be able to do something like this:
	// ```
	// worker_url {env.LINKUP_WORKER_URL}
	// ```
	// which would replace `{env.LINKUP_WORKER_URL}` with the environemnt variable value
	// of LINKUP_WORKER_URL at runtime.
	s.WorkerUrl = strings.TrimRight(caddy.NewReplacer().ReplaceAll(s.WorkerUrl, ""), "/")
	s.Token = caddy.NewReplacer().ReplaceAll(s.Token, "")

	s.client = http.DefaultClient

	return nil
}

func (s *Linkup) Store(_ context.Context, key string, value []byte) error {
	body := map[string]interface{}{"data_base64": base64.StdEncoding.EncodeToString(value)}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/linkup/certificate-cache/%s", s.WorkerUrl, url.PathEscape(key))
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.Token))

	res, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("failed to read body: %v", err)
		}

		s.Logger.Infow("Received a non-200 response from worker",
			"method", "PUT",
			"url", url,
			"response_status", res.StatusCode,
			"response_body", string(resBody),
		)

		return fmt.Errorf("worker responded with HTTP %d", res.StatusCode)
	}

	return nil
}

func (s *Linkup) Load(ctx context.Context, key string) ([]byte, error) {
	certificateCache, err := s.LoadCache(ctx, key)
	if err != nil {
		return nil, err
	}

	decodedValue, err := certificateCache.DecodedData()
	if err != nil {
		return nil, err
	}

	return decodedValue, nil
}

func (s *Linkup) Delete(ctx context.Context, key string) error {
	url := fmt.Sprintf("%s/linkup/certificate-cache/%s", s.WorkerUrl, url.PathEscape(key))
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.Token))

	res, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("failed to read body: %v", err)
		}

		s.Logger.Infow("Received a non-200 response from worker",
			"method", "DELETE",
			"url", url,
			"response_status", res.StatusCode,
			"response_body", string(resBody),
		)

		return fmt.Errorf("worker responded with HTTP %d", res.StatusCode)
	}

	return nil
}

func (s *Linkup) Exists(ctx context.Context, key string) bool {
	_, err := s.Load(ctx, key)

	return err == nil
}

func (s *Linkup) List(_ context.Context, path string, recursive bool) ([]string, error) {
	url := fmt.Sprintf("%s/linkup/certificate-cache/keys", s.WorkerUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.Token))

	query := req.URL.Query()
	query.Add("path", path)
	query.Add("recursive", fmt.Sprintf("%t", recursive))
	req.URL.RawQuery = query.Encode()

	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}

	if res.StatusCode != 200 {
		s.Logger.Infow("Received a non-200 response from worker",
			"method", "GET",
			"url", url,
			"response_status", res.StatusCode,
			"response_body", string(resBody),
		)

		return nil, fmt.Errorf("worker responded with HTTP %d", res.StatusCode)
	}

	var keys []string
	err = json.Unmarshal(resBody, &keys)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

func (s *Linkup) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	cache, err := s.LoadCache(ctx, key)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	return certmagic.KeyInfo{
		Key:        key,
		Size:       int64(cache.Size),
		Modified:   time.Unix(int64(cache.LastModified), 0),
		IsTerminal: true,
	}, nil
}

func (s *Linkup) Lock(ctx context.Context, key string) error {
	// noop
	return nil
}

func (s *Linkup) Unlock(_ context.Context, key string) error {
	// noop
	return nil
}

func (s *Linkup) LoadCache(ctx context.Context, key string) (CertificateCacheResponse, error) {
	url := fmt.Sprintf("%s/linkup/certificate-cache/%s", s.WorkerUrl, url.PathEscape(key))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return CertificateCacheResponse{}, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.Token))

	res, err := s.client.Do(req)
	if err != nil {
		return CertificateCacheResponse{}, err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return CertificateCacheResponse{}, fmt.Errorf("failed to read body: %v", err)
	}

	if res.StatusCode != 200 {
		s.Logger.Infow("Received a non-200 response from worker",
			"method", "GET",
			"url", url,
			"response_status", res.StatusCode,
			"response_body", string(resBody),
		)

		if res.StatusCode == 404 {
			return CertificateCacheResponse{}, fs.ErrNotExist
		} else {
			return CertificateCacheResponse{}, fmt.Errorf("worker responded with HTTP %d", res.StatusCode)
		}
	}

	var certificateCache CertificateCacheResponse
	err = json.Unmarshal(resBody, &certificateCache)
	if err != nil {
		return CertificateCacheResponse{}, err
	}

	return certificateCache, nil
}
