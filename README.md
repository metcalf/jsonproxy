jsonproxy
=========

jsonproxy provides a filtering proxy over a JSON-over-HTTP API. It allows
for assigning more granualar permissions to an existing API.

jsonproxy only works for proxies that return exclusively JSON content and
use the "username" field of HTTP basic auth for all authentication. 

# Role configuration

TODO

# API

jsonproxy has its own HTTP-over-JSON API. All of the API paths are prefixed
by the value in the `JSONPROXY_API_PREFIX` environment variable or the default
prefix, `jsonproxy`.

## POST /<prefix>/keys

Generates an API key to be used with the jsonproxy. It encrypts a list of
roles along with a string to be used as the HTTP basic auth username for
communicating with the upstream API. When using the proxy, base64 decode
the key returned from this endpoint and use it as the HTTP basic auth
username for your request.

### Parameters

JSON object with the following keys:

* roles[[]string]: List of roles that the newly generated key will inclue
* api_key[string]: API key for the upstream API.

### Returns

JSON object with the following keys:

* key[string]: Base64-encoded key to be used as the HTTP basic auth password
  when making requests to the proxy.
* roles[[]string]: Echoed from the request
* api_key[string]: API key for the upstream API.
