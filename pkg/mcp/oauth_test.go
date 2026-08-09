package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obot-platform/nanobot/pkg/safehttp"
	"golang.org/x/oauth2"
)

type recordingTokenStorage struct {
	config *oauth2.Config
	token  *oauth2.Token
}

func (r *recordingTokenStorage) GetTokenConfig(context.Context, string) (*oauth2.Config, *oauth2.Token, error) {
	return r.config, r.token, nil
}

func (r *recordingTokenStorage) SetTokenConfig(_ context.Context, _ string, config *oauth2.Config, token *oauth2.Token) error {
	r.config = config
	r.token = token
	return nil
}

func (*recordingTokenStorage) DeleteTokenConfig(context.Context, string) error {
	return nil
}

func TestGetOAuthMetadata(t *testing.T) {
	var serverURL string
	var pathMetadataRequested, rootMetadataRequested atomic.Bool
	const (
		clientName  = "Test Client"
		redirectURL = "http://localhost/callback"
	)
	protectedResourceMetadata := json.RawMessage(`{"resource":"resource","authorization_servers":["issuer"],"scopes_supported":["read"]}`)
	authorizationServerMetadata := json.RawMessage(`{"issuer":"issuer","authorization_endpoint":"authorize","token_endpoint":"token","registration_endpoint":"register","response_types_supported":["code"],"client_id_metadata_document_supported":true}`)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/mcp":
			if req.Method != http.MethodPost {
				http.NotFound(w, req)
				return
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/mcp":
			pathMetadataRequested.Store(true)
			http.NotFound(w, req)
		case "/.well-known/oauth-protected-resource":
			rootMetadataRequested.Store(true)
			if req.Header.Get("X-Test") != "value" {
				http.Error(w, "missing test header", http.StatusBadRequest)
				return
			}
			metadata := map[string]any{}
			if err := json.Unmarshal(protectedResourceMetadata, &metadata); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			metadata["resource"] = serverURL
			metadata["authorization_servers"] = []string{serverURL + "/issuer"}
			_ = json.NewEncoder(w).Encode(metadata)
		case "/.well-known/oauth-authorization-server/issuer":
			if req.Header.Get("X-Test") != "value" {
				http.Error(w, "missing test header", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(authorizationServerMetadata)
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	result, err := GetOAuthMetadataWithClient(t.Context(), safehttp.NewClient(false, true, true), Server{
		BaseURL: ts.URL + "/mcp",
		Headers: map[string]string{
			"X-Test": "value",
		},
	}, clientName, redirectURL)
	if err != nil {
		t.Fatal(err)
	}

	if result.ProtectedResourceMetadataURL != ts.URL+"/.well-known/oauth-protected-resource" {
		t.Fatalf("unexpected protected resource URL: %s", result.ProtectedResourceMetadataURL)
	}
	if !pathMetadataRequested.Load() || !rootMetadataRequested.Load() {
		t.Fatalf("expected path and root protected resource metadata URLs to be requested")
	}
	if result.AuthorizationServerMetadataURL != ts.URL+"/.well-known/oauth-authorization-server/issuer" {
		t.Fatalf("unexpected authorization server URL: %s", result.AuthorizationServerMetadataURL)
	}
	if len(result.ProtectedResourceMetadata) == 0 {
		t.Fatalf("expected protected resource metadata")
	}
	if string(result.AuthorizationServerMetadata) != string(authorizationServerMetadata) {
		t.Fatalf("unexpected authorization server metadata: %s", result.AuthorizationServerMetadata)
	}
	if !result.DynamicClientRegistration {
		t.Fatalf("expected dynamic client registration support")
	}
	if !result.ClientIDMetadataDocumentSupported {
		t.Fatalf("expected client ID metadata document support")
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal oauth metadata: %v", err)
	}
	var resultFields map[string]json.RawMessage
	if err := json.Unmarshal(resultJSON, &resultFields); err != nil {
		t.Fatalf("failed to parse oauth metadata: %v", err)
	}
	if string(resultFields["clientIdMetadataDocumentSupported"]) != "true" {
		t.Fatalf("expected clientIdMetadataDocumentSupported JSON field, got %s", resultFields["clientIdMetadataDocumentSupported"])
	}
	var clientRegistration ClientRegistrationMetadata
	if err := json.Unmarshal(result.ClientRegistration, &clientRegistration); err != nil {
		t.Fatalf("failed to parse client registration metadata: %v", err)
	}
	if clientRegistration.ClientName != clientName {
		t.Fatalf("unexpected client name: %s", clientRegistration.ClientName)
	}
	if len(clientRegistration.RedirectURIs) != 1 || clientRegistration.RedirectURIs[0] != redirectURL {
		t.Fatalf("unexpected redirect URIs: %v", clientRegistration.RedirectURIs)
	}
	if clientRegistration.Scope != "read" {
		t.Fatalf("unexpected scope: %s", clientRegistration.Scope)
	}
	if !slices.Equal(clientRegistration.GrantTypes, []string{"authorization_code"}) {
		t.Fatalf("unexpected grant types: %v", clientRegistration.GrantTypes)
	}
}

func TestOAuthResourceMetadataURLs(t *testing.T) {
	tests := []struct {
		name               string
		baseURL            string
		authenticateHeader string
		wantURLs           []string
		wantScope          string
	}{
		{
			name:    "defaults to path-specific then root metadata without an auth header",
			baseURL: "https://mcp.example.com/mcp",
			wantURLs: []string{
				"https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
				"https://mcp.example.com/.well-known/oauth-protected-resource",
			},
		},
		{
			name:               "retains challenge scope for default metadata URLs",
			baseURL:            "https://mcp.example.com/v1/mcp",
			authenticateHeader: `Bearer scope="read write"`,
			wantURLs: []string{
				"https://mcp.example.com/.well-known/oauth-protected-resource/v1/mcp",
				"https://mcp.example.com/.well-known/oauth-protected-resource",
			},
			wantScope: "read write",
		},
		{
			name:               "uses advertised resource metadata URL exclusively",
			baseURL:            "https://mcp.example.com/mcp",
			authenticateHeader: `Bearer resource_metadata="https://auth.example.com/resources/mcp" scope="read"`,
			wantURLs:           []string{"https://auth.example.com/resources/mcp"},
			wantScope:          "read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls, scope, err := oauthResourceMetadataURLs(tt.baseURL, tt.authenticateHeader)
			if err != nil {
				t.Fatal(err)
			}

			gotURLs := make([]string, len(urls))
			for i, u := range urls {
				gotURLs[i] = u.String()
			}
			if !slices.Equal(gotURLs, tt.wantURLs) {
				t.Fatalf("unexpected resource metadata URLs: got %v, want %v", gotURLs, tt.wantURLs)
			}
			if scope != tt.wantScope {
				t.Fatalf("unexpected scope: got %q, want %q", scope, tt.wantScope)
			}
		})
	}
}

func TestAuthServerMetadataToClientRegistrationFiltersGrantTypes(t *testing.T) {
	tests := []struct {
		name      string
		supported []string
		want      []string
	}{
		{
			name:      "keeps only authorization code and refresh token",
			supported: []string{"client_credentials", "refresh_token", "authorization_code", "implicit"},
			want:      []string{"authorization_code", "refresh_token"},
		},
		{
			name:      "omits unsupported grant types",
			supported: []string{"client_credentials", "implicit"},
		},
		{
			name:      "keeps refresh token when advertised",
			supported: []string{"refresh_token"},
			want:      []string{"refresh_token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientRegistration := AuthServerMetadataToClientRegistration(AuthorizationServerMetadata{
				GrantTypesSupported: tt.supported,
			}, "", "", "")
			if !slices.Equal(clientRegistration.GrantTypes, tt.want) {
				t.Fatalf("unexpected grant types: got %v, want %v", clientRegistration.GrantTypes, tt.want)
			}
		})
	}
}

func TestGetOAuthMetadataMissingProtectedResource(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	result, err := GetOAuthMetadataWithClient(t.Context(), safehttp.NewClient(false, true, true), Server{BaseURL: ts.URL}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.ProtectedResourceMetadataURL != "" || len(result.ProtectedResourceMetadata) != 0 {
		t.Fatalf("expected empty result for missing protected resource metadata: %#v", result)
	}
}

func TestGetOAuthMetadataInitializeSuccessDeletesSession(t *testing.T) {
	var deleted, metadataFetched atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/mcp":
			w.Header().Set(SessionIDHeader, "session-1")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result":  map[string]any{},
			})
		case req.Method == http.MethodDelete && req.URL.Path == "/mcp":
			if req.Header.Get(SessionIDHeader) != "session-1" {
				http.Error(w, "missing session id", http.StatusBadRequest)
				return
			}
			deleted.Store(true)
			w.WriteHeader(http.StatusAccepted)
		case req.URL.Path == "/.well-known/oauth-protected-resource":
			metadataFetched.Store(true)
			http.Error(w, "metadata should not be fetched after successful initialize", http.StatusInternalServerError)
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()

	result, err := GetOAuthMetadataWithClient(t.Context(), safehttp.NewClient(false, true, true), Server{BaseURL: ts.URL + "/mcp"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.ProtectedResourceMetadataURL != "" || len(result.ProtectedResourceMetadata) != 0 {
		t.Fatalf("expected empty result after successful initialize: %#v", result)
	}
	if !deleted.Load() {
		t.Fatalf("expected successful initialize session to be deleted")
	}
	if metadataFetched.Load() {
		t.Fatalf("metadata should not be fetched after successful initialize")
	}
}

func TestGetOAuthMetadataAuthorizationServerNoRegistration(t *testing.T) {
	var serverURL string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/.well-known/oauth-protected-resource":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resource": serverURL,
			})
		case "/.well-known/oauth-authorization-server":
			http.NotFound(w, req)
		case "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(`{"issuer":"issuer","authorization_endpoint":"authorize","token_endpoint":"token","response_types_supported":["code"]}`))
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	result, err := GetOAuthMetadataWithClient(t.Context(), safehttp.NewClient(false, true, true), Server{BaseURL: ts.URL}, "", "")
	if err != nil {
		t.Fatal(err)
	}

	if result.AuthorizationServerMetadataURL != ts.URL+"/.well-known/openid-configuration" {
		t.Fatalf("unexpected authorization server fallback URL: %s", result.AuthorizationServerMetadataURL)
	}
	if result.DynamicClientRegistration {
		t.Fatalf("expected no dynamic client registration support")
	}
}

type testClientCredLookup struct {
	clientID     string
	clientSecret string
	calls        int
}

func (l *testClientCredLookup) Lookup(context.Context, string) (string, string, error) {
	l.calls++
	return l.clientID, l.clientSecret, nil
}

func TestResolveClientInfoUsesClientIDMetadataDocument(t *testing.T) {
	lookup := &testClientCredLookup{
		clientID:     "static-client-id",
		clientSecret: "static-client-secret",
	}
	o := &oauth{
		clientIDMetadataDocument: "https://client.example/oauth-client-metadata.json",
		clientLookup:             lookup,
	}

	clientInfo, err := o.resolveClientInfo(t.Context(), "test-server", oauthMetadataDiscovery{
		ProtectedResourceMetadata: protectedResourceMetadata{
			AuthorizationServers: []string{"https://issuer.example"},
		},
		AuthorizationServerMetadata: AuthorizationServerMetadata{
			ClientIDMetadataDocumentSupported: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if clientInfo.ClientID != o.clientIDMetadataDocument {
		t.Fatalf("expected metadata document client ID %q, got %q", o.clientIDMetadataDocument, clientInfo.ClientID)
	}
	if clientInfo.ClientSecret != "" {
		t.Fatalf("expected empty client secret, got %q", clientInfo.ClientSecret)
	}
	if lookup.calls != 0 {
		t.Fatalf("static client lookup should not be called, got %d calls", lookup.calls)
	}
}

func TestResolveClientInfoFallsBackWhenClientIDMetadataDocumentUnsupported(t *testing.T) {
	lookup := &testClientCredLookup{
		clientID:     "static-client-id",
		clientSecret: "static-client-secret",
	}
	o := &oauth{
		clientIDMetadataDocument: "https://client.example/oauth-client-metadata.json",
		clientLookup:             lookup,
	}

	clientInfo, err := o.resolveClientInfo(t.Context(), "test-server", oauthMetadataDiscovery{
		ProtectedResourceMetadata: protectedResourceMetadata{
			AuthorizationServers: []string{"https://issuer.example"},
		},
		AuthorizationServerMetadata: AuthorizationServerMetadata{
			ClientIDMetadataDocumentSupported: false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if clientInfo.ClientID != lookup.clientID {
		t.Fatalf("expected static client ID %q, got %q", lookup.clientID, clientInfo.ClientID)
	}
	if clientInfo.ClientSecret != lookup.clientSecret {
		t.Fatalf("expected static client secret %q, got %q", lookup.clientSecret, clientInfo.ClientSecret)
	}
	if lookup.calls != 1 {
		t.Fatalf("expected one static client lookup, got %d calls", lookup.calls)
	}
}

func TestTokenEndpointAuthStyleUsesParamsWithoutClientSecret(t *testing.T) {
	if got := tokenEndpointAuthStyle("client_secret_basic", false); got != oauth2.AuthStyleInParams {
		t.Fatalf("expected params auth style without client secret, got %v", got)
	}
}

func TestTokenEndpointAuthStyleHonorsClientSecretMethods(t *testing.T) {
	tests := []struct {
		method string
		want   oauth2.AuthStyle
	}{
		{method: "client_secret_basic", want: oauth2.AuthStyleInHeader},
		{method: "client_secret_post", want: oauth2.AuthStyleInParams},
		{method: "", want: oauth2.AuthStyleAutoDetect},
	}

	for _, tt := range tests {
		if got := tokenEndpointAuthStyle(tt.method, true); got != tt.want {
			t.Fatalf("expected auth style %v for method %q, got %v", tt.want, tt.method, got)
		}
	}
}

func TestAuthCodeURLRequestsOfflineAccessForEntra(t *testing.T) {
	const (
		entraAuthorize    = "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize"
		nonEntraAuthorize = "https://example.com/oauth/authorize"
		zohoAuthorize     = "https://mcp.zoho.com/oauth/v2/auth"
		resourceURL       = "https://mcp.example.com/mcp"
	)

	tests := []struct {
		name           string
		authorizeURL   string
		scopes         []string
		wantScope      string
		wantResource   bool
		wantAccessType bool
	}{
		{
			name:           "entra gets offline_access appended",
			authorizeURL:   entraAuthorize,
			scopes:         []string{"https://api.fabric.microsoft.com/.default"},
			wantScope:      "https://api.fabric.microsoft.com/.default offline_access",
			wantAccessType: true,
		},
		{
			name:           "entra does not duplicate offline_access",
			authorizeURL:   entraAuthorize,
			scopes:         []string{"https://graph.microsoft.com/User.Read", "offline_access"},
			wantScope:      "https://graph.microsoft.com/User.Read offline_access",
			wantAccessType: true,
		},
		{
			name:           "entra without scopes is left alone",
			authorizeURL:   entraAuthorize,
			scopes:         nil,
			wantScope:      "",
			wantAccessType: true,
		},
		{
			name:           "non-entra keeps its scopes and gets the resource parameter",
			authorizeURL:   nonEntraAuthorize,
			scopes:         []string{"read", "write"},
			wantScope:      "read write",
			wantResource:   true,
			wantAccessType: true,
		},
		{
			name:         "zoho keeps its scopes and does not get access_type",
			authorizeURL: zohoAuthorize,
			scopes:       []string{"read"},
			wantScope:    "read",
			wantResource: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := &oauth2.Config{
				ClientID: "client-id",
				Scopes:   slices.Clone(tt.scopes),
				Endpoint: oauth2.Endpoint{AuthURL: tt.authorizeURL},
			}

			raw, err := AuthCodeURL(conf, tt.authorizeURL, resourceURL, "state", "verifier")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("failed to parse authorization URL: %v", err)
			}
			query := parsed.Query()

			if got := query.Get("scope"); got != tt.wantScope {
				t.Fatalf("unexpected scope: got %q, want %q", got, tt.wantScope)
			}
			if got := query.Has("resource"); got != tt.wantResource {
				t.Fatalf("unexpected resource parameter presence: got %v, want %v", got, tt.wantResource)
			}
			if got := query.Get("access_type") == "offline"; got != tt.wantAccessType {
				t.Fatalf("unexpected access_type parameter presence: got %v, want %v", got, tt.wantAccessType)
			}
			if !slices.Equal(conf.Scopes, tt.scopes) {
				t.Fatalf("AuthCodeURL mutated the caller's scopes: got %v, want %v", conf.Scopes, tt.scopes)
			}
		})
	}
}

func TestExpiredStoredTokenRefreshesBeforeProtectedRequest(t *testing.T) {
	var tokenRequests, protectedRequests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/token":
			tokenRequests.Add(1)
			if err := req.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.Form.Get("grant_type") != "refresh_token" {
				http.Error(w, "expected refresh_token grant", http.StatusBadRequest)
				return
			}
			if req.Form.Get("refresh_token") != "entra-refresh-token" {
				http.Error(w, "missing stored refresh token", http.StatusBadRequest)
				return
			}
			if req.Form.Has("scope") {
				http.Error(w, "refresh request unexpectedly included scope", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"renewed-access-token","token_type":"Bearer","expires_in":3600,"refresh_token":"rotated-refresh-token"}`))
		case "/mcp":
			protectedRequests.Add(1)
			if req.Header.Get("Authorization") != "Bearer renewed-access-token" {
				http.Error(w, "request did not use refreshed access token", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	storage := &recordingTokenStorage{}
	config := &oauth2.Config{
		ClientID: "entra-client-id",
		Endpoint: oauth2.Endpoint{
			TokenURL:  server.URL + "/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	expired := &oauth2.Token{
		AccessToken:  "expired-access-token",
		RefreshToken: "entra-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Hour),
	}

	client := oauth2.NewClient(t.Context(), newTokenSource(t.Context(), storage, server.URL+"/mcp", config, expired))
	response, err := client.Get(server.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected protected-resource status: %s", response.Status)
	}
	if tokenRequests.Load() != 1 {
		t.Fatalf("expected one refresh request, got %d", tokenRequests.Load())
	}
	if protectedRequests.Load() != 1 {
		t.Fatalf("expected one protected request, got %d", protectedRequests.Load())
	}
	if storage.token == nil || storage.token.AccessToken != "renewed-access-token" || storage.token.RefreshToken != "rotated-refresh-token" {
		t.Fatalf("refreshed token was not persisted: %#v", storage.token)
	}
}
