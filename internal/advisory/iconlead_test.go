package advisory

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

func iconRow(product string, extra map[string]string) map[string]string {
	r := map[string]string{"product": product, "template": "favicon-detect", "matcher": product, "many": "1", "icon": "1"}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

func iconObs(extra map[string]any, rows ...map[string]string) types.StoredObservation {
	row := map[string]any{"url": "http://app.test:8080/", "ip": "10.0.0.5", "title": "Welcome", "favicon": "1278323681", "favicon_url": "http://app.test:8080/favicon.ico", "detected": rows}
	for k, v := range extra {
		row[k] = v
	}
	return obsOf("azhaq-http", "http", row)
}

// A product only an icon's hash named is not a service of the name: no
// listener row, no version, nothing for an advisory or a read to start from.
// It is one lead that says what matched.
func TestIconAloneIsALeadNotAService(t *testing.T) {
	obs := []types.StoredObservation{iconObs(nil, iconRow("gitlab", map[string]string{"ask": "GET /users/sign_in answered 404 and no template of the product matched"}))}
	if got := ServicesAnyVersion(obs); len(got) != 0 {
		t.Errorf("an icon named a service: %+v", got)
	}
	if got := Services(obs); len(got) != 0 {
		t.Errorf("an icon named a service with a version: %+v", got)
	}
	leads := IconLeads(obs)
	if len(leads) != 1 || leads[0].Says() != "favicon matches gitlab" || leads[0].Host != "app.test" || leads[0].Port != 8080 {
		t.Fatalf("leads %+v", leads)
	}
	if len(leads[0].Asked) != 1 || leads[0].Asked[0] != "gitlab: GET /users/sign_in answered 404 and no template of the product matched" {
		t.Errorf("what was asked: %v", leads[0].Asked)
	}
}

// An icon an older azhaq stored, with no mark, is still an icon.
func TestIconRowWithoutTheMarkIsStillALead(t *testing.T) {
	r := iconRow("gitlab", nil)
	delete(r, "icon")
	obs := []types.StoredObservation{iconObs(nil, r)}
	if got := ServicesAnyVersion(obs); len(got) != 0 {
		t.Errorf("a stored favicon-detect row named a service: %+v", got)
	}
	if len(IconLeads(obs)) != 1 {
		t.Errorf("no lead for the stored row")
	}
}

// Another source for the same product keeps it an identification: the title,
// a header, a technology or a template of the product on a read.
func TestIconWithOtherEvidenceStaysAnIdentification(t *testing.T) {
	for name, c := range map[string]struct {
		extra   map[string]any
		product string
	}{
		"title":      {map[string]any{"title": "Grafana"}, "grafana"},
		"server":     {map[string]any{"server": "GitLab/1.0"}, "gitlab"},
		"technology": {map[string]any{"tech": []string{"GitLab"}}, "gitlab"},
		"generator":  {map[string]any{"generator": "GitLab 16.0"}, "gitlab"},
	} {
		t.Run(name, func(t *testing.T) {
			obs := []types.StoredObservation{iconObs(c.extra, iconRow(c.product, nil))}
			if leads := IconLeads(obs); len(leads) != 0 {
				t.Errorf("a lead beside other evidence: %+v", leads)
			}
			found := false
			for _, s := range ServicesAnyVersion(obs) {
				found = found || identity(s.Product) == identity(c.product)
			}
			if !found {
				t.Errorf("the product other evidence names is not a service: %+v", ServicesAnyVersion(obs))
			}
		})
	}
	// A template of the product that matched on a read of the sweep.
	obs := []types.StoredObservation{
		iconObs(nil, iconRow("gitlab", nil)),
		obsOf("azhaq-paths", "detected", map[string]any{"url": "http://app.test:8080/", "path": "/users/sign_in", "status": 200,
			"detected": []map[string]string{{"product": "Gitlab", "template": "gitlab-detect"}}}),
	}
	if leads := IconLeads(obs); len(leads) != 0 {
		t.Errorf("a lead beside a template of the product that matched: %+v", leads)
	}
	if got := appsBy(ServicesAnyVersion(obs)); len(got) != 1 {
		t.Errorf("services %v", keysOf(got))
	}
}

// A read of the product that a template matched settles the icon: the row
// is a detection with the version the template read, and Services has it.
func TestConfirmedIconIsADetectionWithItsVersion(t *testing.T) {
	r := iconRow("gitlab", map[string]string{"ask": "GET /users/sign_in answered 200 and the template gitlab-detect matched", "version": "16.4.1"})
	delete(r, "icon")
	obs := []types.StoredObservation{iconObs(nil, r)}
	if leads := IconLeads(obs); len(leads) != 0 {
		t.Errorf("a settled icon is a lead: %+v", leads)
	}
	got := appsBy(Services(obs))
	s, ok := got["app.test:8080 gitlab"]
	if !ok || s.Version != "16.4.1" {
		t.Fatalf("services %v", keysOf(got))
	}
	if want := "detection template: favicon-detect; GET /users/sign_in answered 200 and the template gitlab-detect matched"; s.Banner != want {
		t.Errorf("banner %q", s.Banner)
	}
}

// One hash several products share names all of them.
func TestSharedIconNamesEveryProduct(t *testing.T) {
	obs := []types.StoredObservation{iconObs(nil, iconRow("fortinet forticlient", nil), iconRow("FortiOS Admin", nil))}
	leads := IconLeads(obs)
	if len(leads) != 1 || leads[0].Says() != "favicon matches fortinet forticlient or FortiOS Admin" {
		t.Errorf("leads %+v", leads)
	}
	// One of them named by the title leaves the others a lead.
	obs = []types.StoredObservation{iconObs(map[string]any{"title": "Grafana"}, iconRow("grafana", nil), iconRow("jira", nil))}
	leads = IconLeads(obs)
	if len(leads) != 1 || leads[0].Says() != "favicon matches jira" {
		t.Errorf("leads %+v", leads)
	}
}
