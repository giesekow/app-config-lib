package configlib

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

var PRODUCT_PREFIX = "spine-q"
var ENV_CONFIG_PATH = "SPINEQ_CONFIG_PATH"
var COMPANY_PREFIX = ".bonescreen"

// -------------------------
// Config path helpers
// -------------------------
func GetConfigPath() string {
	var defaultPath string
	if IsWindows() {
		home, _ := os.UserHomeDir()
		defaultPath = filepath.Join(home, COMPANY_PREFIX, PRODUCT_PREFIX)
	} else {
		defaultPath = filepath.Join("/", "etc", PRODUCT_PREFIX)
	}

	cpath := os.Getenv(ENV_CONFIG_PATH)
	if cpath == "" {
		cpath = defaultPath
	}
	cpath = ExpandPath(cpath)
	return cpath
}

// -------------------------
// Load/Save TOML config
// -------------------------
func LoadConfig(customPath ...string) (map[string]any, error) {
	data := make(map[string]any)

	baseConfigPath := GetConfigPath()
	var configPath string
	if len(customPath) == 0 || customPath[0] == "" {
		configPath = filepath.Join(baseConfigPath, "config.toml")
	} else {
		configPath = filepath.Clean(customPath[0])
	}

	if f, err := os.Open(configPath); err == nil {
		defer f.Close()
		if err := toml.NewDecoder(f).Decode(&data); err != nil {
			return data, fmt.Errorf("unable to parse TOML: %v", err)
		}
	}

	// Handle decryption
	encryptionMap := GetConfigField(data, "encryption").(map[string]any)
	enabled, _ := encryptionMap["enabled"].(bool)
	keyPath, _ := encryptionMap["key"].(string)
	if keyPath != "" {
		keyPath = ExpandPath(keyPath)
	}

	if enabled && keyPath != "" {
		if _, err := os.Stat(keyPath); err == nil {
			keyPair, err := LoadKeyPair(keyPath)
			if err == nil {
				encFields := getEncryptedFields(data)
				for _, k := range encFields {
					if val := GetConfigField(data, k); val != nil {
						decVal, err := DecryptData(keyPair, val.(string))
						if err == nil {
							data = SetConfigField(data, k, decVal)
						} else {
							fmt.Printf("Unable to decrypt %s\n", k)
						}
					}
				}
			} else {
				fmt.Printf("Unable to load key pair at %s, decryption skipped\n", keyPath)
			}
		} else {
			fmt.Printf("Key pair at %s does not exist, decryption skipped\n", keyPath)
		}
	}

	return data, nil
}

func SaveConfig(config map[string]any, customPath string) (bool, string) {
	configCopy := deepCopy(config)

	encryptionMap := GetConfigField(configCopy, "encryption").(map[string]any)
	enabled, _ := encryptionMap["enabled"].(bool)
	keyPath, _ := encryptionMap["key"].(string)
	if keyPath != "" {
		keyPath = os.ExpandEnv(keyPath)
	}

	if enabled && keyPath != "" {
		if _, err := os.Stat(keyPath); err == nil {
			keyPair, err := LoadKeyPair(keyPath)
			if err == nil {
				encFields := getEncryptedFields(configCopy)
				for _, k := range encFields {
					if val := GetConfigField(configCopy, k); val != nil {
						encVal, err := EncryptData(keyPair, val.(string))
						if err == nil {
							configCopy = SetConfigField(configCopy, k, encVal)
						} else {
							fmt.Printf("Unable to encrypt %s\n", k)
						}
					}
				}
			} else {
				fmt.Printf("Unable to load key pair at %s\n", keyPath)
			}
		} else {
			fmt.Printf("Key pair at %s does not exist, encryption skipped!\n", keyPath)
		}
	}

	baseConfigPath := GetConfigPath()
	var configPath string
	if customPath == "" {
		configPath = filepath.Join(baseConfigPath, "config.toml")
	} else {
		configPath = filepath.Clean(ExpandPath(customPath))
	}

	f, err := os.Create(configPath)
	if err != nil {
		return false, err.Error()
	}
	defer f.Close()

	if err := toml.NewEncoder(f).Encode(configCopy); err != nil {
		return false, err.Error()
	}

	return true, "success"
}

// GetConfigField extracts a value from a nested config map.
// key can be:
// - string: dot notation, e.g. "encryption.tls.cert_file"
// - []any: [key, defaultValue] (similar to Python list)
// name is optional, used for "workers" lookup
func GetConfigField(config map[string]any, key any, name ...string) any {
	var actKey any
	var defValue any

	// Handle list [key, default]
	switch k := key.(type) {
	case []any:
		if len(k) > 0 {
			actKey = k[0]
		}
		if len(k) > 1 {
			defValue = k[1]
		}
	case []string:
		if len(k) > 0 {
			actKey = k[0]
		}
		if len(k) > 1 {
			defValue = k[1]
		}
	default:
		actKey = key
	}

	// If actKey is a function/callable, invoke it
	if fn, ok := actKey.(func(map[string]any) any); ok {
		v := fn(config)
		if v == nil {
			return defValue
		}
		return v
	}

	// If actKey is string, handle dot notation
	actStr, ok := actKey.(string)
	if !ok {
		return defValue
	}

	parts := splitDot(actStr)

	// Special "workers" handling
	if len(parts) > 0 && parts[0] == "workers" && len(name) > 0 && name[0] != "" {
		if workersRaw, ok := config["workers"].(map[string]any); ok {
			if instancesRaw, ok := workersRaw["instance"].([]any); ok {
				var curValue any
				for _, inst := range instancesRaw {
					if instMap, ok := inst.(map[string]any); ok {
						if n, ok := instMap["name"].(string); ok && n == name[0] {
							curValue = instMap
							break
						}
					}
				}

				if curValue != nil {
					for _, p := range parts[1:] {
						curValue = descend(curValue, p)
						if curValue == nil {
							break
						}
					}
					if curValue != nil {
						return curValue
					}
				}
			}
		}
	}

	// General traversal
	var cur any = config
	for _, p := range parts {
		cur = descend(cur, p)
		if cur == nil {
			return defValue
		}
	}

	return cur
}

func GetConfigFieldString(config map[string]any, key any, name ...string) string {
	value := GetConfigField(config, key, name...)
	if value == nil {
		return ""
	}

	if s, ok := value.(string); ok {
		return s
	}

	return ""
}

func GetConfigFieldStringStripped(config map[string]any, key any, name ...string) string {
	value := GetConfigField(config, key, name...)
	return GetStripped(value)
}

func GetConfigFieldBool(config map[string]any, key any, name ...string) bool {
	value := GetConfigField(config, key, name...)
	return GetBool(value)
}

// -------------------------
// Helper functions
// -------------------------

// splitDot splits a dot-notated key
func splitDot(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ".")
}

// descend moves one level down in map or slice
func descend(cur any, key string) any {
	switch val := cur.(type) {
	case map[string]any:
		return val[key]
	case []any:
		if idx, err := strconv.Atoi(key); err == nil {
			if idx >= 0 && idx < len(val) {
				return val[idx]
			}
		}
	}
	return nil
}

func SetConfigField(config map[string]any, key string, value any) map[string]any {
	parts := strings.Split(key, ".")
	cur := config
	for i, part := range parts {
		if i == len(parts)-1 {
			if value == nil {
				delete(cur, part)
			} else {
				cur[part] = value
			}
		} else {
			if next, ok := cur[part].(map[string]any); ok {
				cur = next
			} else {
				newMap := make(map[string]any)
				cur[part] = newMap
				cur = newMap
			}
		}
	}
	return config
}

// -------------------------
// Encryption helpers
// -------------------------
func getEncryptedFields(config map[string]any) []string {
	raw := GetConfigField(config, "encryption.fields")
	res := []string{}
	if rawArr, ok := raw.([]any); ok {
		for _, r := range rawArr {
			s := fmt.Sprintf("%v", r)
			if s != "encryption" && !strings.HasPrefix(s, "encryption.") {
				res = append(res, s)
			}
		}
	}
	return res
}

// -------------------------
// Deep copy utility
// -------------------------
func deepCopy(src map[string]any) map[string]any {
	dst := make(map[string]any)
	for k, v := range src {
		switch val := v.(type) {
		case map[string]any:
			dst[k] = deepCopy(val)
		case []any:
			newArr := make([]any, len(val))
			for i, elem := range val {
				if m, ok := elem.(map[string]any); ok {
					newArr[i] = deepCopy(m)
				} else {
					newArr[i] = elem
				}
			}
			dst[k] = newArr
		default:
			dst[k] = v
		}
	}
	return dst
}

func GetStripped(value any) string {
	if value == nil {
		return ""
	}
	svalue := fmt.Sprintf("%v", value)
	svalue = strings.TrimSpace(svalue)
	return svalue
}

func GetBool(value any) bool {
	if value == nil {
		return false
	}

	if b, ok := value.(bool); ok {
		return b
	}

	return false
}

// -------------------------
// Set Encryption Key
// -------------------------
func SetEncryptionKey(config map[string]any, keyPath string) map[string]any {
	config = SetConfigField(config, "encryption.key", keyPath)
	return config
}

func GetEncryptionKey(config map[string]any) string {
	path := GetConfigField(config, "encryption.key")
	if path != nil {
		if strPath, ok := path.(string); ok {
			return ExpandPath(strPath)
		}
	}

	return ""
}

func SetEncryptionFields(config map[string]any, fields []string) map[string]any {
	config = SetConfigField(config, "encryption.fields", fields)
	return config
}

func GetAPIURL(config map[string]any) string {
	url := GetConfigField(config, "api.url")
	if url != nil {
		if urlStr, ok := url.(string); ok {
			return urlStr
		}
	}

	host := GetConfigField(config, []interface{}{"api.host", "localhost"})
	port := GetConfigField(config, []interface{}{"api.port", 3030})
	proto := GetConfigField(config, []interface{}{"api.proto", "http"})

	urlStr := fmt.Sprintf("%v://%v:%v", proto, host, port)

	return urlStr
}

func GetAuthURL(config map[string]any) string {
	url := GetConfigField(config, "keycloak.url")
	if url != nil {
		if urlStr, ok := url.(string); ok {
			return urlStr
		}
	}

	host := GetConfigField(config, []interface{}{"keycloak.host", "localhost"})
	port := GetConfigField(config, []interface{}{"keycloak.port", 8084})
	proto := GetConfigField(config, []interface{}{"keycloak.proto", "http"})

	urlStr := fmt.Sprintf("%v://%v:%v", proto, host, port)

	return urlStr
}

func GetFrontendURL(config map[string]any) string {
	url := GetConfigField(config, "frontend.url")
	if url != nil {
		if urlStr, ok := url.(string); ok {
			return urlStr
		}
	}

	host := GetConfigField(config, []interface{}{"keycloak.host", "localhost"})
	port := GetConfigField(config, []interface{}{"keycloak.port", 8084})
	proto := GetConfigField(config, []interface{}{"keycloak.proto", "http"})

	if hostStr, ok := host.(string); ok && hostStr == "0.0.0.0" {
		host = "localhost"
	}

	urlStr := fmt.Sprintf("%v://%v:%v", proto, host, port)

	return urlStr
}

func GetTLSIsEnabled(config map[string]any) bool {
	enabled := GetConfigField(config, "encryption.tls.enabled")
	if benabled, ok := enabled.(bool); ok && benabled {
		return true
	}
	return false
}

func SetTLSIsEnabled(config map[string]any, enabled bool) map[string]any {
	return SetConfigField(config, "encryption.tls.enabled", enabled)
}

func GetTLSCertFile(config map[string]any) string {
	value := GetConfigField(config, "encryption.tls.cert_file")
	if file, ok := value.(string); ok && file != "" {
		return ExpandPath(file)
	}
	return ""
}

func GetTLSKeyFile(config map[string]any) string {
	value := GetConfigField(config, "encryption.tls.key_file")
	if file, ok := value.(string); ok && file != "" {
		return ExpandPath(file)
	}
	return ""
}

func GetTLSCombinedFile(config map[string]any) string {
	value := GetConfigField(config, "encryption.tls.combined_file")
	if file, ok := value.(string); ok && file != "" {
		return ExpandPath(file)
	}
	return ""
}

func GetTLSCAFile(config map[string]any) string {
	value := GetConfigField(config, "encryption.tls.ca_file")
	if file, ok := value.(string); ok && file != "" {
		return ExpandPath(file)
	}
	return ""
}

func GetTLSTrustedCA(config map[string]any) bool {
	value := GetConfigField(config, "encryption.tls.trusted_ca")
	if enabled, ok := value.(bool); ok && enabled {
		return true
	}
	return false
}

func SetTLSCertFile(config map[string]any, certPath string) map[string]any {
	return SetConfigField(config, "encryption.tls.cert_file", certPath)
}

func SetTLSKeyFile(config map[string]any, keyPath string) map[string]any {
	return SetConfigField(config, "encryption.tls.key_file", keyPath)
}

func SetTLSCombinedFile(config map[string]any, combinedPath string) map[string]any {
	return SetConfigField(config, "encryption.tls.combined_file", combinedPath)
}

func SetTLSCAFile(config map[string]any, caPath string) map[string]any {
	return SetConfigField(config, "encryption.tls.ca_file", caPath)
}

func SetTLSTrustedCA(config map[string]any, isTrusted bool) map[string]any {
	return SetConfigField(config, "encryption.tls.trusted_ca", isTrusted)
}

func GetMongoURL(config map[string]any) string {
	value := GetConfigField(config, "mongo.url")
	vurl := GetStripped(value)
	if vurl != "" {
		return vurl
	}

	host := GetConfigField(config, []interface{}{"mongo.host", "localhost"})
	port := GetConfigField(config, []interface{}{"mongo.port", 27017})
	proto := GetConfigField(config, []interface{}{"mongo.proto", "mongodb"})

	user := GetConfigField(config, []interface{}{"mongo.username", ""})
	password := GetConfigField(config, []interface{}{"mongo.password", ""})
	authSource := GetConfigField(config, []interface{}{"mongo.auth_source", "admin"})
	auth := GetConfigField(config, []interface{}{"mongo.auth", false})

	enableTLS := GetConfigField(config, []interface{}{"mongo.enable_tls", false})
	caFile := GetConfigField(config, []interface{}{"mongo.ca_file", ""})
	clientFile := GetConfigField(config, []interface{}{"mongo.tls_client_file", ""})

	if caFile == nil {
		caFile = GetTLSCAFile(config)
	}

	if clientFile == nil {
		clientFile = GetTLSCombinedFile(config)
	}

	var uObj *url.URL

	if GetBool(auth) {
		if GetStripped(user) != "" && GetStripped(password) != "" && GetStripped(authSource) != "" {
			uObj = &url.URL{
				Scheme: GetStripped(proto),
				User:   url.UserPassword(url.QueryEscape(GetStripped(user)), url.QueryEscape(GetStripped(password))),
				Host:   fmt.Sprintf("%v:%v", host, port),
				Path:   "/",
			}

			// Add query parameters
			q := uObj.Query()
			q.Set("authSource", GetStripped(authSource))
			uObj.RawQuery = q.Encode()
		}
	}

	if uObj == nil {
		uObj = &url.URL{
			Scheme: GetStripped(proto),
			Host:   fmt.Sprintf("%v:%v", host, port),
		}
	}

	if GetBool(enableTLS) {
		q := uObj.Query()
		q.Set("tls", "true")

		if GetStripped(caFile) != "" {
			q.Set("tlsCAFile", ExpandPath(GetStripped(caFile)))
		}

		if (GetStripped(clientFile)) != "" {
			q.Set("tlsCertificateKeyFile", ExpandPath(GetStripped(clientFile)))
		}
		uObj.RawQuery = q.Encode()
	}

	return uObj.String()
}

func GetServiceBasedCertificates(config map[string]any, service string) map[string]any {
	data := map[string]any{
		"trusted_ca": false,
	}

	// Get CA File
	caFile := GetConfigField(config, fmt.Sprintf("%s.ca_file", service))
	trustedCA := GetConfigField(config, fmt.Sprintf("%s.trusted_ca", service))

	if GetStripped(caFile) == "" {
		caFile = GetTLSCAFile(config)
		trustedCA = GetTLSTrustedCA(config)
	}

	if GetStripped(caFile) != "" {
		data["ca"] = ExpandPath(GetStripped(caFile))
		data["trusted_ca"] = GetBool(trustedCA)
	}

	// Get Cert File
	certFile := GetConfigField(config, fmt.Sprintf("%s.cert_file", service))
	if GetStripped(certFile) == "" {
		certFile = GetTLSCertFile(config)
	}
	if GetStripped(certFile) != "" {
		data["cert"] = ExpandPath(GetStripped(certFile))
	}

	// Get Key File
	keyFile := GetConfigField(config, fmt.Sprintf("%s.key_file", service))
	if GetStripped(keyFile) == "" {
		keyFile = GetTLSKeyFile(config)
	}
	if GetStripped(keyFile) != "" {
		data["key"] = ExpandPath(GetStripped(keyFile))
	}

	// Get Combined File
	combinedFile := GetConfigField(config, fmt.Sprintf("%s.combined_file", service))
	if GetStripped(combinedFile) == "" {
		combinedFile = GetTLSCombinedFile(config)
	}
	if GetStripped(combinedFile) != "" {
		data["combined"] = ExpandPath(GetStripped(combinedFile))
	}

	return data
}
