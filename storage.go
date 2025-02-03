package caddy_storage_cf_kv

import (
	"context"

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

type Linkup struct {
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
	s.WorkerUrl = caddy.NewReplacer().ReplaceAll(s.WorkerUrl, "")
	s.Token = caddy.NewReplacer().ReplaceAll(s.Token, "")

	return nil
}

func (s *Linkup) Store(_ context.Context, key string, value []byte) error {
	// POST /linkup/certificate-cache
	return nil
}

func (s *Linkup) Load(_ context.Context, key string) ([]byte, error) {
	// GET /linkup/certificate-cache/{key} - TODO: Does this work? Some keys might have '/', for example
	return []byte{}, nil
}

func (s *Linkup) Delete(ctx context.Context, key string) error {
	// DELETE /linkup/certificate-cache/{key}
	return nil
}

func (s *Linkup) Exists(ctx context.Context, key string) bool {
	// use `s.Load()`
	return false
}

func (s *Linkup) List(_ context.Context, path string, recursive bool) ([]string, error) {
	// GET /linkup/certificate-cache
	return []string{}, nil
}

func (s *Linkup) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	// use `s.Load()`
	return certmagic.KeyInfo{}, nil
}

func (s *Linkup) Lock(ctx context.Context, key string) error {
	// noop
	return nil
}

func (s *Linkup) Unlock(_ context.Context, key string) error {
	// noop
	return nil
}

func (s Linkup) String() string {
	return ""
}
