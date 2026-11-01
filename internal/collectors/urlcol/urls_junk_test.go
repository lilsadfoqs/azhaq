package urlcol

import "testing"

// The shapes a default urls run printed from an archive of scanner traffic.
func TestCleanDropsFuzzerLogsTraversalAndGluedSQL(t *testing.T) {
	for _, u := range []string{
		"http://vulnweb.com/FUZZMultiple",
		"http://vulnweb.com/listproducts.php?cat=FUZZ",
		"http://testasp.vulnweb.com/t/fit.txt?.tst5-ExcellenthdghrvubMaleSanskrit/../Gen",
		"http://testphp.vulnweb.com/%CB%93%E2%86%92FUZZ",
		"http://testphp.vulnweb.com/a.php?%CB%93%E2%86%92artist=FUZZ000003:C=200",
		"http://testphp.vulnweb.com/artists.php?artist=1union%20select%20group_concat%28schema_name%29%20from%20information_schema.schemata",
	} {
		if got, why, ok := cleanWhy(u, "vulnweb.com", false); ok || why == "" {
			t.Errorf("kept=%v why=%q %s", ok, why, got)
		}
	}
	if _, why, ok := cleanWhy("http://testphp.vulnweb.com/artists.php?artist=1", "vulnweb.com", false); !ok || why != "" {
		t.Errorf("a plain URL: kept=%v why=%q", ok, why)
	}
}
