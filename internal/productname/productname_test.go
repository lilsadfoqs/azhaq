package productname

import "testing"

func TestToken(t *testing.T) {
	for in, want := range map[string][2]string{
		"Apache/2.4.49 (Unix) PHP/7.4":      {"Apache", "2.4.49"},
		"Apache httpd 2.4.1":                {"Apache httpd", "2.4.1"},
		"Apache-Coyote/1.1":                 {"Apache-Coyote", "1.1"},
		"ApacheBench/2.3":                   {"ApacheBench", "2.3"},
		"Apache-HttpClient/4.5.13 (Java/1)": {"Apache-HttpClient", "4.5.13"},
		"Apache Tomcat/9.0.50":              {"Apache Tomcat", "9.0.50"},
		"Apache Traffic Server/9.1.0":       {"Apache Traffic Server", "9.1.0"},
		"Apache Traffic Server":             {"Apache Traffic Server", ""},
		"Apache (Ubuntu)":                   {"Apache", ""},
		"Jetty(9.4.51.v20230217)":           {"Jetty", "9.4.51.v20230217"},
		"Microsoft-IIS/10.0":                {"Microsoft-IIS", "10.0"},
		"Mongrel 1.1.5":                     {"Mongrel", "1.1.5"},
		"nginx":                             {"nginx", ""},
		"ECS (dcb/7F83)":                    {"ECS", ""},
		"ASP.NET":                           {"ASP.NET", ""},
		"1.1 varnish":                       {"", ""},
		"":                                  {"", ""},
	} {
		n, v := Token(in)
		if [2]string{n, v} != want {
			t.Errorf("Token(%q) = %q,%q want %q", in, n, v, want)
		}
	}
}

func TestNames(t *testing.T) {
	for _, c := range []struct {
		value, product string
		want           bool
	}{
		{"Apache/2.4.1", "Apache", true},
		{"Apache httpd 2.4.1", "Apache", true},
		{"Apache HTTP Server/2.4", "Apache", true},
		{"apache/2.4.1", "Apache HTTP Server", true},
		{"Apache-Coyote/1.1", "Apache", false},
		{"ApacheBench/2.3", "Apache", false},
		{"Apache-HttpClient/4.5.13", "Apache", false},
		{"Apache Tomcat/9.0.50", "Apache", false},
		{"Apache Traffic Server/9.1.0", "Apache", false},
		{"Apache/2.4.1", "Apache Tomcat", false},
		{"Apache Tomcat/9.0.50", "Tomcat", true},
		{"Microsoft-IIS/10.0", "Microsoft IIS", true},
		{"Microsoft-HTTPAPI/2.0", "Microsoft IIS", false},
		{"Boa/0.94.14", "Boa Web Server", true},
		{"Serv-U/15.2.1", "SolarWinds Serv-U File Server", true},
		{"nginx/1.24.0", "TURN Server", false},
		{"gunicorn/20.1.0", "Gunicorn Server", true},
		{"1.1 whatever", "Apache", true}, // no name to judge
	} {
		if got := Names(c.value, c.product); got != c.want {
			t.Errorf("Names(%q, %q) = %v want %v", c.value, c.product, got, c.want)
		}
	}
}

func TestSame(t *testing.T) {
	yes := [][2]string{
		{"Apache ActiveMQ", "ActiveMQ"}, {"ActiveMQ", "Apache ActiveMQ"}, {"Apache Spark", "Spark"},
		{"MikroTik RouterOS", "RouterOS"}, {"Apache Hadoop YARN", "Hadoop YARN"},
		{"Apache", "Apache HTTP Server"}, {"Apache httpd", "Apache"}, {"Apache Tomcat", "apache-tomcat"},
		{"Microsoft IIS", "IIS"},
	}
	for _, p := range yes {
		if !Same(p[0], p[1]) {
			t.Errorf("Same(%q, %q) = false", p[0], p[1])
		}
	}
	no := [][2]string{
		{"Apache", "Apache ActiveMQ"}, {"Apache ActiveMQ", "Apache"}, {"Apache Spark", "Apache Flink"},
		{"YARN", "Hadoop YARN"}, {"Apache HTTP Server", "HTTP Server"}, {"Apache Server", "Microsoft Server"},
		{"Apache-Coyote", "Apache"}, {"", ""},
	}
	for _, p := range no {
		if Same(p[0], p[1]) {
			t.Errorf("Same(%q, %q) = true", p[0], p[1])
		}
	}
}
