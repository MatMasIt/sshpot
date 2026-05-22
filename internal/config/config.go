// Package config loads and validates the honeypot configuration.
package config

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"os/user"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration structure.
type Config struct {
	Server    Server    `toml:"server"`
	Logging   Logging   `toml:"logging"`
	RateLimit RateLimit `toml:"ratelimit"`
	Process   Process   `toml:"process"`
}

type Server struct {
	Listen           string   `toml:"listen"`
	Banner           string   `toml:"banner"`
	OutputText       string   `toml:"output_text"`
	HandshakeTimeout Duration `toml:"handshake_timeout"`
	// How long to wait for a shell request after accepting a session channel.
	ShellRequestTimeout Duration `toml:"shell_request_timeout"`
	// Small pause before writing output to the client (e.g. terminal render delay).
	PreOutputDelay Duration `toml:"pre_output_delay"`
	// Time to wait after writing output before closing the session.
	PostOutputDelay Duration `toml:"post_output_delay"`
	bannerTemplate  *template.Template
	outputTemplate  *template.Template
}

func (s Server) RenderBanner() (string, error) {
	if s.bannerTemplate == nil {
		tmpl, err := parseTextTemplate(s.Banner)
		if err != nil {
			return "", err
		}
		return renderTemplate(tmpl)
	}
	return renderTemplate(s.bannerTemplate)
}

func (s Server) RenderOutputText() (string, error) {
	tmpl := s.outputTemplate
	if tmpl == nil {
		parsed, err := parseTextTemplate(s.OutputText)
		if err != nil {
			return "", err
		}
		tmpl = parsed
	}
	rendered, err := renderTemplate(tmpl)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(rendered, "\n", "\r\n"), nil
}

type Logging struct {
	Path string `toml:"path"`
}

type RateLimit struct {
	BucketCount  uint32   `toml:"bucket_count"`
	RestInterval Duration `toml:"rest_interval"`
}

// Duration accepts either a TOML duration string (for example "30s") or a
// numeric value interpreted as seconds.
type Duration time.Duration

func (d *Duration) UnmarshalTOML(v any) error {
	// Require durations to be specified as strings with units, e.g. "500ms", "2s".
	value, ok := v.(string)
	if !ok {
		return fmt.Errorf("duration must be a string with unit, got %T", v)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) TimeDuration() time.Duration {
	return time.Duration(d)
}

type Process struct {
	User  string `toml:"user"`
	Group string `toml:"group"`
}

func (p *Process) Resolve() (uid, gid int, err error) {
	var (
		uidStr string
		gidStr string
	)

	// user
	if id, err := strconv.Atoi(p.User); err == nil {
		uid = id
	} else {
		u, err := user.Lookup(p.User)
		if err != nil {
			return -1, -1, fmt.Errorf("lookup user %q: %w", p.User, err)
		}
		uidStr = u.Uid
		uid, err = strconv.Atoi(uidStr)
		if err != nil {
			return -1, -1, fmt.Errorf("invalid uid %q: %w", uidStr, err)
		}
	}

	// group
	if id, err := strconv.Atoi(p.Group); err == nil {
		gid = id
	} else {
		g, err := user.LookupGroup(p.Group)
		if err != nil {
			return -1, -1, fmt.Errorf("lookup group %q: %w", p.Group, err)
		}
		gidStr = g.Gid
		gid, err = strconv.Atoi(gidStr)
		if err != nil {
			return -1, -1, fmt.Errorf("invalid gid %q: %w", gidStr, err)
		}
	}

	return uid, gid, nil
}

// Load reads and validates a TOML config file.
func Load(path string) (*Config, error) {
	cfg := &Config{}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	if _, err := toml.NewDecoder(f).Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	return cfg, validate(cfg)
}

func validate(c *Config) error {
	if c.Server.Listen == "" {
		return fmt.Errorf("server.listen must not be empty")
	}
	if c.Server.OutputText == "" {
		return fmt.Errorf("server.output_text must not be empty")
	}
	if err := c.Server.compileTemplates(); err != nil {
		return err
	}
	if c.Server.HandshakeTimeout <= 0 {
		return fmt.Errorf("server.handshake_timeout must be positive")
	}
	if c.Server.ShellRequestTimeout <= 0 {
		return fmt.Errorf("server.shell_request_timeout must be positive")
	}
	if c.Server.PreOutputDelay < 0 {
		return fmt.Errorf("server.pre_output_delay must be non-negative")
	}
	if c.Server.PostOutputDelay < 0 {
		return fmt.Errorf("server.post_output_delay must be non-negative")
	}
	if c.Logging.Path == "" {
		return fmt.Errorf("logging.path must not be empty")
	}
	if c.RateLimit.BucketCount == 0 {
		return fmt.Errorf("ratelimit.bucket_count must be greater than 0")
	}
	if c.RateLimit.RestInterval <= 0 {
		return fmt.Errorf("ratelimit.rest_interval must be positive")
	}
	if c.Process.User == "" {
		return fmt.Errorf("process.user must not be empty")
	}
	if c.Process.Group == "" {
		return fmt.Errorf("process.group must not be empty")
	}
	return nil
}

func parseTextTemplate(text string) (*template.Template, error) {
	return template.New("sshpot").Funcs(textTemplateFuncs()).Parse(text)
}

func renderTemplate(tmpl *template.Template) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, nil); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (s *Server) compileTemplates() error {
	bannerTemplate, err := parseTextTemplate(s.Banner)
	if err != nil {
		return fmt.Errorf("server.banner: %w", err)
	}

	outputTemplate, err := parseTextTemplate(s.OutputText)
	if err != nil {
		return fmt.Errorf("server.output_text: %w", err)
	}

	s.bannerTemplate = bannerTemplate
	s.outputTemplate = outputTemplate
	return nil
}

func textTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"nowUTC": func() string {
			return time.Now().UTC().Format("Mon Jan 2 15:04:05 UTC 2006")
		},
		"randInt": func(min, max int) (int, error) {
			if max < min {
				return 0, fmt.Errorf("randInt: max %d is less than min %d", max, min)
			}
			return min + rand.Intn(max-min+1), nil
		},
		"randFloat": func(min, max float64) (float64, error) {
			if max < min {
				return 0, fmt.Errorf("randFloat: max %f is less than min %f", max, min)
			}
			return min + rand.Float64()*(max-min), nil
		},
		"randPercent": func() float64 {
			return rand.Float64() * 100
		},
		"chance": func(percent float64) (bool, error) {
			if percent < 0 || percent > 100 {
				return false, fmt.Errorf("chance: percent must be between 0 and 100, got %f", percent)
			}
			return rand.Float64()*100 < percent, nil
		},
		"randDate": func(min, max string) (string, error) {
			minTime, err := time.Parse("2006-01-02", min)
			if err != nil {
				return "", fmt.Errorf("oldDate: invalid min date %q: %w", min, err)
			}
			maxTime, err := time.Parse("2006-01-02", max)
			if err != nil {
				return "", fmt.Errorf("oldDate: invalid max date %q: %w", max, err)
			}
			if maxTime.Before(minTime) {
				return "", fmt.Errorf("oldDate: max date %q is before min date %q", max, min)
			}
			diff := maxTime.Sub(minTime)
			randomDuration := time.Duration(rand.Int63n(int64(diff)))
			randomTime := minTime.Add(randomDuration)
			return randomTime.Format("Mon Jan 2 15:04:05 2006"), nil
		},
		"diskSize": func(min, max float32) (string, error) {
			if max < min {
				return "", fmt.Errorf("diskSize: max %f is less than min %f", max, min)
			}
			size := min + rand.Float32()*(max-min)
			if size < 100 {
				return fmt.Sprintf("%.2fGB ", size), nil
			}
			return fmt.Sprintf("%.2fGB", size), nil
		},
		"randIP": func(placeholder string) string {
			// placeholder is like "192.168.x.x" where x is replaced with a random number between 0 and 255
			parts := strings.Split(placeholder, ".")
			for i, part := range parts {
				if part == "x" {
					parts[i] = strconv.Itoa(rand.Intn(256))
				}
			}
			return strings.Join(parts, ".")
		},
	}
}
