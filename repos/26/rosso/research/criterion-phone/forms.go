package main

import "encoding/json"

// formsPayload mirrors the JSON the Auth0 Forms SDK posts alongside every
// form action. The custom prompt has no fields, so formData stays empty.
type formsPayload struct {
	FormData map[string]any `json:"formData"`
	MetaData struct {
		Navigator struct {
			UserAgent string `json:"userAgent"`
			Language  string `json:"language"`
		} `json:"navigator"`
		Navigation struct {
			Referer string `json:"referer"`
			Location struct {
				Protocol     string            `json:"protocol"`
				Hostname     string            `json:"hostname"`
				Port         string            `json:"port"`
				Host         string            `json:"host"`
				Pathname     string            `json:"pathname"`
				Search       string            `json:"search"`
				SearchParams map[string]string `json:"searchParams"`
				Hash         string            `json:"hash"`
				Href         string            `json:"href"`
			} `json:"location"`
			Analytics struct {
				GA map[string]any `json:"ga"`
			} `json:"analytics"`
		} `json:"navigation"`
		View struct {
			Screen struct {
				Height int `json:"height"`
				Width  int `json:"width"`
			} `json:"screen"`
			Window struct {
				Height int `json:"height"`
				Width  int `json:"width"`
			} `json:"window"`
		} `json:"view"`
	} `json:"metaData"`
}

func (s *Session) formsPayload() ([]byte, error) {
	promptPath := "/u/custom-prompt/" + s.PromptID
	promptURL := authBase + promptPath + "?state=" + s.PromptState

	p := formsPayload{FormData: map[string]any{}}
	p.MetaData.Navigator.UserAgent = browserUA
	p.MetaData.Navigator.Language = "en-US"
	p.MetaData.Navigation.Referer = authBase + "/u/login/password?state=" + urlQueryEscape(s.LoginState)
	p.MetaData.Navigation.Location.Protocol = "https:"
	p.MetaData.Navigation.Location.Hostname = "login.criterion.com"
	p.MetaData.Navigation.Location.Host = "login.criterion.com"
	p.MetaData.Navigation.Location.Pathname = promptPath
	p.MetaData.Navigation.Location.Search = "?state=" + s.PromptState
	p.MetaData.Navigation.Location.SearchParams = map[string]string{"state": s.PromptState}
	p.MetaData.Navigation.Location.Href = promptURL
	p.MetaData.Navigation.Analytics.GA = map[string]any{}
	p.MetaData.View.Screen.Height, p.MetaData.View.Screen.Width = 851, 393
	p.MetaData.View.Window.Height, p.MetaData.View.Window.Width = 751, 393
	return json.Marshal(p)
}
