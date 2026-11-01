package browser

import (
	"os"
	"path/filepath"
)

// quietPrefs is the Preferences of a new profile: Chrome's sign-in, safe
// browsing lookups, password leak checks and suggestion services asked for
// nothing, as no flag turns them off.
const quietPrefs = `{
 "signin": {"allowed": false, "allowed_on_next_startup": false, "interception_enabled": false},
 "safebrowsing": {"enabled": false, "enhanced": false},
 "profile": {"password_manager_enabled": false, "password_manager_leak_detection": false},
 "credentials_enable_service": false,
 "search": {"suggest_enabled": false},
 "alternate_error_pages": {"enabled": false},
 "url_keyed_anonymized_data_collection": {"enabled": false},
 "translate": {"enabled": false},
 "browser": {"promotions_enabled": false, "default_browser_setting_enabled": false}
}
`

// seedProfile writes quietPrefs into dir when it holds no profile yet. A
// profile that exists (a user's -chrome-profile, signed in sessions and
// all) is left as it is.
func seedProfile(dir string) error {
	prefs := filepath.Join(dir, "Default", "Preferences")
	if _, err := os.Stat(prefs); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(prefs), 0o700); err != nil {
		return err
	}
	return os.WriteFile(prefs, []byte(quietPrefs), 0o600)
}
