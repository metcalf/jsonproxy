package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
)

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// Proxy provides configuration for proxying an underlying HTTP-over-JSON API.
// The underlying HTTP proxy is based on
// https://golang.org/src/net/http/httputil/reverseproxy.go.
type Proxy struct {
	KeyOpener   func([]byte) (*Key, error)
	Roles       map[string]Role
	UpstreamURL *url.URL
	Transport   http.RoundTripper
}

var unauthorizedResp = errResponse{Error: errDetail{
	Code: "unauthorized",
}}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key, err := p.authenticate(r)
	if err != nil {
		resp := unauthorizedResp
		resp.Error.Message = err.Error()

		respond(w, resp, http.StatusUnauthorized)
		return
	}

	var matches []Rule
	for _, role := range key.Roles {
		rr, ok := p.Roles[role]
		if !ok {
			resp := unauthorizedResp
			resp.Error.Message = fmt.Sprintf("Role %s does not exist", role)

			respond(w, resp, http.StatusUnauthorized)
			return
		}

		for pattern, rule := range rr {
			if matched, err := path.Match(pattern, r.URL.Path); err != nil {
				panic(err)
			} else if !matched {
				continue
			}

			for _, method := range rule.Methods {
				if method == "*" || method == r.Method {
					matches = append(matches, rule)
					break
				}
			}
		}
	}

	if len(matches) == 0 {
		resp := unauthorizedResp
		resp.Error.Message = "You do not have permission to access this resource"

		respond(w, resp, http.StatusUnauthorized)
		return
	}

	body, res, err := p.request(r, key.APIKey)
	if err != nil {
		panic(err)
	}

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	w.WriteHeader(res.StatusCode)
	copyHeader(w.Header(), res.Header)

	if res.StatusCode < 300 {
		var err error
		body, err = filterBytes(body, matches)
		if err != nil {
			panic(err)
		}
	}

	w.Write(body)
}

func (p *Proxy) request(r *http.Request, apiKey string) ([]byte, *http.Response, error) {
	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	outreq := new(http.Request)
	*outreq = *r // includes shallow copies of maps, but okay

	outreq.URL = p.UpstreamURL.ResolveReference(r.URL)
	outreq.Host = p.UpstreamURL.Host

	outreq.Proto = "HTTP/1.1"
	outreq.ProtoMajor = 1
	outreq.ProtoMinor = 1
	outreq.Close = false
	outreq.SetBasicAuth(apiKey, "")

	// Remove hop-by-hop headers to the backend.  Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.  This
	// is modifying the same underlying map from r (shallow
	// copied above) so we only copy it if necessary.
	copiedHeaders := false
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			if !copiedHeaders {
				outreq.Header = make(http.Header)
				copyHeader(outreq.Header, r.Header)
				copiedHeaders = true
			}
			outreq.Header.Del(h)
		}
	}

	rc, _ := httputil.DumpRequest(outreq, false)
	log.Println(outreq.URL.String())
	log.Println(string(rc))

	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("Response body: %s", body)

	return body, res, nil
}

func (p *Proxy) authenticate(r *http.Request) (*Key, error) {
	user, _, ok := r.BasicAuth()
	if !ok {
		return nil, errors.New("Unable to parse Authorization header")
	}

	key, err := p.KeyOpener([]byte(user))
	if err != nil {
		return nil, errors.New("Invalid password provided")
	}

	return key, nil
}

func filterBytes(input []byte, rules []Rule) ([]byte, error) {
	var parsed interface{}
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, err
	}

	filtered, _, err := filterJSON(parsed, rules, []string{})
	if err != nil {
		return nil, err
	}

	output, err := json.Marshal(filtered)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func filterJSON(v interface{}, rules []Rule, keys []string) (interface{}, bool, error) {
	// TODO: Should this provide special handling for empty arrays/maps?
	switch vt := v.(type) {
	case []interface{}:
		if len(vt) == 0 {
			break
		}

		var vf []interface{}
		for _, ve := range vt {
			if ve, matched, err := filterJSON(ve, rules, keys); err != nil {
				return nil, false, err
			} else if matched {
				vf = append(vf, ve)
			}
		}
		return vf, len(vf) > 0, nil

	case map[string]interface{}:
		if len(vt) == 0 {
			break
		}

		vf := make(map[string]interface{})
		for k, ve := range vt {
			if ve, matched, err := filterJSON(ve, rules, append(keys, k)); err != nil {
				return nil, false, err
			} else if matched {
				vf[k] = ve
			}
		}
		return vf, len(vf) > 0, nil

	default:
		break
	}

	matched, err := checkFilter(rules, keys)
	if err != nil {
		return nil, false, err
	}
	return v, matched, nil
}

func checkFilter(rules []Rule, keys []string) (bool, error) {
	keyPath := path.Join(keys...)
	for _, rule := range rules {
		for _, keyPattern := range rule.ResponseKeys {
			if matched, err := path.Match(keyPattern, keyPath); err != nil {
				return false, err
			} else if matched {
				return true, nil
			}
		}
	}
	return false, nil
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
