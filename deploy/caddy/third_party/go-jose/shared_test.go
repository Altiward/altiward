package jose

import "github.com/go-jose/go-jose/v3/json"

// getJWK extracts parsed "jwk" from the raw JSON.
func (parsed rawHeader) getJWK() (*JSONWebKey, error) {
	v := parsed[headerJWK]
	if v == nil {
		return nil, nil
	}
	var jwk *JSONWebKey
	err := json.Unmarshal(*v, &jwk)
	if err != nil {
		return nil, err
	}
	return jwk, nil
}
