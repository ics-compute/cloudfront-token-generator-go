package main

import (
	"fmt"
	cf_token_generator "github.com/ics-compute/cloudfront-token-generator-go"
	"github.com/caarlos0/env/v9"
	"net/url"
	"time"
)

type config struct {
	Url       url.URL       `env:"URL"`
	Key       string        `env:"KEY"`
	KeyId     string        `env:"KEY_ID"`
	Exp       time.Duration `env:"EXP" envDefault:"24h"`
	FirstExp  time.Duration `env:"FIRST_EXP" envDefault:"5m"`
	Country   string        `env:"CO" envDefault:""`
	Region    string        `env:"REG" envDefault:""`
	NoSession bool          `env:"NO_SSN" envDefault:"false"`
	UserAgent string        `env:"UA" envDefault:""`
	Referer   string        `env:"REF" envDefault:""`
}

func main() {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		fmt.Printf("%+v\n", err)
	}
	token := cf_token_generator.NewCustomTokenSingleSecret(cfg.KeyId, cfg.Key)

	tokenPolicy := cf_token_generator.DefaultTokenPolicy()
	tokenPolicy.Expiry = cfg.Exp
	tokenPolicy.FirstAccessExpiry = cfg.FirstExp
	tokenPolicy.Session = !cfg.NoSession
	if len(cfg.Country) == 0 {
		tokenPolicy.Country = false
	}
	if len(cfg.Region) == 0 {
		tokenPolicy.Region = false
	}
	var headers []string
	if len(cfg.UserAgent) > 0 {
		headers = append(headers, "user-agent")
	}
	if len(cfg.Referer) > 0 {
		headers = append(headers, "referer")
	}
	tokenPolicy.Headers = headers

	viewerAttrs := &cf_token_generator.ViewerAttributes{
		Country: cfg.Country,
		Region:  cfg.Region,
		Headers: map[string]string{
			"user-agent": cfg.UserAgent,
			"referer":    cfg.Referer,
		},
	}

	url, err := token.GenerateUrlFromViewerAttributes(cfg.Url, cfg.KeyId, tokenPolicy, viewerAttrs)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
	fmt.Printf("URL: %s\n", url)
}
