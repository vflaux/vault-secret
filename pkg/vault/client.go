package vault

import (
	"fmt"
	"path"
	"strings"

	vapi "github.com/hashicorp/vault/api"
)

const (
	KvVersionAuto = 0
	KvVersion1    = 1
	KvVersion2    = 2
)

type Client interface {
	Read(engine int, kvPath string, secretPath string) (map[string]interface{}, error)
}

var _ Client = &SimpleClient{}

type SimpleClient struct {
	client *vapi.Client
}

func NewSimpleClient(client *vapi.Client) *SimpleClient {
	return &SimpleClient{
		client: client,
	}
}

func (c *SimpleClient) Read(kvVersion int, kvPath string, secretPath string) (map[string]interface{}, error) {
	switch kvVersion {
	case KvVersion1:
		sec, err := c.read(path.Join(kvPath, secretPath))
		if err != nil {
			return nil, err
		}
		return sec.Data, nil
	case KvVersion2:
		sec, err := c.read(path.Join(kvPath, "data", secretPath))
		if err != nil {
			return nil, err
		}
		return sec.Data["data"].(map[string]interface{}), nil
	default:
		p := path.Join(kvPath, secretPath)

		pathV1 := path.Join(kvPath, secretPath)
		pathV2 := path.Join(kvPath, "data", secretPath)

		var data map[string]interface{}

		// Trying V1 type URL
		// Might fail (err!=nil with a 403) if policy is for a v2 backend (including /data in the path)
		sec, err := c.read(pathV1)
		if err != nil {
			switch err.(type) {
			case *WrongVersionError:
				// Need a V2 KV type read
				sec, err := c.read(pathV2)
				if err != nil {
					return nil, err
				}

				if sec != nil && sec.Data != nil && sec.Data["data"] != nil {
					// Get the inner data object (v2 KV)
					data = sec.Data["data"].(map[string]interface{})
				}
			default:
				return nil, err
			}
		} else if sec != nil {
			// Get the raw data object (v1 KV)
			data = sec.Data
		} else {
			return nil, &PathNotFound{p}
		}

		return data, nil
	}
}

func (c *SimpleClient) read(path string) (*vapi.Secret, error) {
	sec, err := c.client.Logical().Read(path)

	if err != nil {
		// An unknown error occurred
		return nil, err
	} else if err == nil && sec != nil && contains(sec.Warnings, VaultKVWarning) >= 0 {
		// Calling with a v1 path but needs v2 path
		idx := contains(sec.Warnings, VaultKVWarning)
		return nil, &WrongVersionError{sec.Warnings[idx]}
	} else if err == nil && sec == nil {
		return nil, &PathNotFound{path}
	} else {
		return sec, nil
	}
}

var _ Client = &CachedClient{}

type CachedClient struct {
	SimpleClient
	cache map[string](map[string]interface{})
}

func NewCachedClient(client *vapi.Client) *CachedClient {
	return &CachedClient{
		SimpleClient: SimpleClient{
			client: client,
		},
		cache: make(map[string](map[string]interface{})),
	}
}

func (c *CachedClient) Read(kvVersion int, kvPath string, secretPath string) (map[string]interface{}, error) {
	var err error
	var secret map[string]interface{}

	cacheKey := fmt.Sprintf("%s/%s", kvPath, secretPath)
	if cachedSecret, found := c.cache[cacheKey]; found {
		secret = cachedSecret
		err = nil
	} else {
		secret, err = c.SimpleClient.Read(kvVersion, kvPath, secretPath)
		if err != nil || secret != nil { // only cache value if there is no error or a sec returned
			c.cache[cacheKey] = secret
		}
	}
	return secret, err
}

func (c *CachedClient) Clear() {
	c.cache = make(map[string](map[string]interface{}))
}

// Check wether s contains str or not
func contains(s []string, str string) int {
	for k, v := range s {
		if strings.Contains(v, str) {
			return k
		}
	}
	return -1
}
