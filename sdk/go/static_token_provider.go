package stratium

import "context"

type staticTokenProvider struct {
	token string
}

func newStaticTokenProvider(token string) tokenProvider {
	return &staticTokenProvider{token: token}
}

func (s *staticTokenProvider) GetToken(ctx context.Context) (string, error) {
	return s.token, nil
}
