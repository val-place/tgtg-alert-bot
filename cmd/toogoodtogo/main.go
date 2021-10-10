package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	// flags definition
	fs := pflag.NewFlagSet("default", pflag.ContinueOnError)
	fs.String("email", "", "Email used to login")
	fs.String("password", "", "Password used to login")
	fs.Duration("pull-interval", 1*time.Minute, "pull interval")
	fs.Duration("repeat-after", 6*time.Hour, "repeat notification after for a same item after specified period")
	fs.String("tg-token", "", "Telegram bot token")
	fs.String("chat-id", "", "Telegram chat ID")
	fs.Bool("debug", false, "Set logger level to Debug")
	fs.Bool("trace", false, "Set logger level to Debug")
	fs.Float64("latitude", 0.0, "Latitude. 6 digits after dot")
	fs.Float64("longitude", 0.0, "Latitude. 6 digits after dot")
	fs.String("config", "", "Config path")

	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatal().Msgf("Cannot parse command line arguments: %v", err)
	}

	_ = viper.BindPFlags(fs)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvPrefix("bot")
	viper.AutomaticEnv()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	if p := viper.GetString("config"); p != "" {
		viper.AddConfigPath(p)
	} else {
		panic("config path (-config) is not specified")
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if viper.GetBool("debug") {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if viper.GetBool("trace") {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}

	api := API{Client: &http.Client{Timeout: 10 * time.Second}}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Info().Msg("Config file is not found.")
			if viper.GetString("email") == "" || viper.GetString("password") == "" {
				log.Fatal().Msg("email and password are required to login")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(5*time.Second))
			defer cancel()
			user, err := api.LoginByEmail(ctx, viper.GetString("email"), viper.GetString("password"))
			if err != nil {
				log.Fatal().Msgf("An error occured trying to login by email: %v", err)
			}
			log.Debug().Interface("Logged in as", user).Send()
			viper.Set("user", user)
			log.Debug().Caller().Msg("viper debug")
			viper.Debug()

			cfgPath := os.ExpandEnv(path.Join(viper.GetString("config"), "config.yaml"))
			log.Info().Msg("Config file is not exist yet. Going to create one")
			if _, err := os.Create(cfgPath); err != nil {
				log.Fatal().Msgf("Cannot create config file: %v", err)
			}

			if err := viper.WriteConfig(); err != nil {
				log.Fatal().Msgf("Cannot write config file: %v", err)
			}
		} else {
			log.Info().Msgf("Cannot read config file: %v", err)
		}
	}

	if u, ok := viper.Get("user").(*User); ok {
		log.Debug().Interface("user", u).Msg("We have a user")
		api.User = u
	} else {
		log.Fatal().Msg("cannot retrieve user from config")
	}

	cache := make(map[string]time.Time)
	ticker := time.NewTicker(viper.GetDuration("pull-interval"))
	f := viper.GetDuration("repeat-after")

	for {
		<-ticker.C
		log.Info().Msg("fetching")

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(5*time.Second))
		items, err := api.GetFavoriteItems(ctx)
		if err != nil {
			log.Fatal().Err(err)
		}
		for _, i := range items {
			log.Debug().Interface("item", i).Msg("got item")
			if g, ok := cache[i.Item.ID]; !ok || g.Add(f).Before(time.Now()) {
				cache[i.Item.ID] = time.Now()
				_, _ = http.Get("https://api.telegram.org/bot" + viper.GetString("tg-token") + "/sendMessage?chat_id=" + viper.GetString("chat-id") + "&text=" + url.QueryEscape(i.PP()))
			}
		}
		cancel()

	}
}

type User struct {
	UserID       string
	AccessToken  string
	RefreshToken string
}

func (u *User) Token() string {
	return "Bearer " + u.AccessToken
}

type API struct {
	Client *http.Client
	User   *User
}

type reqHeaders map[string]string

var defaultHeaders = reqHeaders{
	"Host":            "apptoogoodtogo.com",
	"user-agent":      "TGTG/21.9.1 Dalvik/2.1.0(Linux; U; Android 11; Pixel 5 Build/RQ3A.210905.001)",
	"accept-language": "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7",
	"content-type":    "application/json; charset=utf-8",
}

const host = "https://apptoogoodtogo.com"

type price struct {
	Code string  `json:"code"`
	U    float32 `json:"minor_units"`
}

func (p *price) Human() float32 {
	return p.U / 100
}

type pickupInterval struct {
	End   time.Time `json:"end"`
	Start time.Time `json:"start"`
}

type pickupLocationAddress struct {
	Line string `json:"address_line"`
}

type pickupLocation struct {
	Address pickupLocationAddress `json:"address"`
}

type item struct {
	Price price  `json:"price"`
	ID    string `json:"item_id"`
}

type Item struct {
	PlaceName      string         `json:"display_name"`
	Item           item           `json:"item"`
	Count          int            `json:"items_available"`
	PickupLocation pickupLocation `json:"pickup_location"`
	PickupInterval pickupInterval `json:"pickup_interval"`
}

func (i *Item) PP() string {
	loc, _ := time.LoadLocation("Europe/Warsaw")

	return fmt.Sprintf("Hurry! Take %d bags at %s for %.2f PLN\nPickup at: %s - %s\nLocation: %s\n",
		i.Count,
		i.PlaceName,
		i.Item.Price.Human(),
		i.PickupInterval.Start.In(loc).String(),
		i.PickupInterval.End.In(loc).String(),
		i.PickupLocation,
	)
}

// GetFavoriteItems
func (api *API) GetFavoriteItems(ctx context.Context) ([]*Item, error) {
	// {\"diet_categories\":[],\"discover\":false,\"favorites_only\":true,\"hidden_only\":false,\"item_categories\":[],\"origin\":{\"latitude\":54.350187,\"longitude\":18.650536},\"page\":1,\"page_size\":100,\"pickup_earliest\":null,\"pickup_latest\":null,\"radius\":3,\"search_phrase\":null,\"user_id\":\"63184840\",\"we_care_only\":false,\"with_stock_only\":true}
	payload, err := json.Marshal(map[string]interface{}{
		"user_id": api.User.UserID,
		"origin": map[string]float64{
			"latitude":  viper.GetFloat64("latitude"),
			"longitude": viper.GetFloat64("longitude"),
		},
		"radius":          3.0,
		"page_size":       100,
		"page":            1,
		"discover":        false,
		"favorites_only":  true,
		"item_categories": []interface{}{},
		"diet_categories": []interface{}{},
		"pickup_earliest": nil,
		"pickup_latest":   nil,
		"search_phrase":   nil,
		"with_stock_only": true,
		"hidden_only":     false,
		"we_care_only":    false,
	})
	if err != nil {
		return []*Item{}, fmt.Errorf("failed to prepare payload to get favorite items: %v", err)
	}

	log.Trace().Bytes("payload", payload).Str("f", "GET_FAVORITE_ITEMS").Msg("")
	req, err := http.NewRequestWithContext(ctx, "POST", host+"/api/item/v7/", bytes.NewReader(payload))
	if err != nil {
		return []*Item{}, fmt.Errorf("cannot build request for refresh token: %v", err)
	}
	req.Header.Set("Authorization", api.User.Token())
	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}
	log.Debug().Bytes("payload", payload).Msg("Requesting favorite items")
	log.Debug().Interface("headers", req.Header).Msg("Request headers")
	var resp *http.Response
	resp, err = api.Client.Do(req)
	if err != nil {
		return []*Item{}, fmt.Errorf("failed to get favorite items: %v", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 400 {
		log.Info().Str("status", resp.Status).Msg("Token is expired. Going to refresh")
		log.Trace().Interface("body", resp.Body).Msg("")
		if err := api.RefreshToken(ctx); err != nil {
			return []*Item{}, fmt.Errorf("token is expired, cannot get new one: %v", err)
		}
		req.Header.Set("Authorization", api.User.Token())

		resp, err = api.Client.Do(req)
		if err != nil {
			return []*Item{}, fmt.Errorf("failed to get favorite items: %v", err)
		}
	}
	defer resp.Body.Close()
	log.Debug().Str("response status", resp.Status).Msg("got response from API")
	log.Debug().Interface("response headers", resp.Header).Msg("got response from API")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []*Item{}, fmt.Errorf("cannot read response body: %v", err)
	}

	type items struct {
		Items []*Item `json:"items"`
	}

	var result items
	if err := json.Unmarshal(body, &result); err != nil {
		return []*Item{}, fmt.Errorf("cannot unmarshall response: %v", err)
	}
	log.Debug().Interface("body", result).Msg("Got response from api")

	return result.Items, nil
}

func (api *API) RefreshToken(ctx context.Context) error {
	log.Info().Interface("user", api.User).Msg("refreshing token")
	if api.User.RefreshToken == "" {
		return fmt.Errorf("Token is empty")
	}

	payload, err := json.Marshal(map[string]string{
		"refresh_token": api.User.RefreshToken,
	})
	if err != nil {
		return fmt.Errorf("failed to refresh token: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", host+"/api/auth/v2/token/refresh", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("cannot build request for refresh token: %v", err)
	}
	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}
	log.Info().Bytes("payload", payload).Msg("refreshing token")
	resp, err := api.Client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %v", err)
	}
	defer resp.Body.Close()
	log.Debug().Str("response status", resp.Status).Msg("got response from API")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("cannot read response body: %v", err)
	}
	log.Trace().Bytes("body", body).Msg("Got following response body")

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("cannot unmarshall response: %v", err)
	}
	log.Debug().Interface("body", result).Msg("Got response from api")
	api.User.AccessToken = result["access_token"].(string)
	api.User.RefreshToken = result["refresh_token"].(string)

	// TODO: Move this side-effects somewhere
	viper.Set("user", api.User)
	if err := viper.WriteConfig(); err != nil {
		log.Debug().Msgf("Cannot write config file: %v", err)
	}

	return nil
}

func (api *API) LoginByEmail(ctx context.Context, email, password string) (*User, error) {
	payload, err := json.Marshal(map[string]string{
		"device_type": "ANDROID",
		"email":       email,
		"password":    password,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to login by email: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", host+"/api/auth/v2/loginByEmail", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("cannot build request for login by email: %v", err)
	}
	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}

	log.Info().Bytes("payload", payload).Msg("performing login by email")
	resp, err := api.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform login request: %v", err)
	}
	defer resp.Body.Close()

	log.Debug().Str("response status", resp.Status).Msg("got response from API")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response body: %v", err)
	}
	log.Trace().Bytes("body", body).Msg("Got following response body")

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("cannot unmarshall response: %v", err)
	}
	log.Debug().Interface("body", result).Msg("Got response from api")

	startupData := result["startup_data"].(map[string]interface{})
	user := startupData["user"].(map[string]interface{})

	return &User{
		UserID:       user["user_id"].(string),
		AccessToken:  result["access_token"].(string),
		RefreshToken: result["refresh_token"].(string),
	}, nil
}
