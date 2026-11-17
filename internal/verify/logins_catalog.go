package verify

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

// The catalog of -verify-logins: every published default credential pair
// and every unauthenticated-read resource it asks about, each with the
// one vendor or advisory page that states it. No pair here is guessed
// and no entry stands for a wordlist: a product not in this list gets no
// check. Products were picked from the ones azhaq already fingerprints
// (internal/wappalyzer, internal/cpedetect) and identifies at the
// protocol level (internal/verify, internal/portscan), never from a lab
// image list.
//
// An attempt is accepted only against two controls sent first on the same
// request, one with no credential and one with a random wrong one (see
// DefaultLogin.Attempt): so each Path is a resource the product gates, and a
// Success rule says what the gated answer holds. A path or a rule that a
// refusal also meets proves nothing and is caught there, not here.
//
// Mode's request shape and Success's judgement are this package's own
// engineering of how each product's sign-in is asked and read; only the
// credential pair (User, Pass) and the fact that the resource needs a
// sign-in are the vendor's claim, and Source is where it is made.

func basicMarker(markers ...string) func(status int, body []byte) bool {
	return func(status int, body []byte) bool {
		return status == 200 && bodyHasAny(body, markers)
	}
}

var defaultLogins = []DefaultLogin{
	{
		ID: "rabbitmq-guest-guest", Product: "RabbitMQ", Source: "https://www.rabbitmq.com/docs/access-control",
		// Ports: https://www.rabbitmq.com/docs/networking (Port Access)
		Ports: []int{5672, 5671, 15672, 15671, 4369, 25672},
		User:  "guest", Pass: "guest", Mode: ModeBasic, Path: "/api/overview",
		Success: basicMarker("rabbitmq_version", "management_version"),
	},
	{
		ID: "activemq-admin-admin", Product: "ActiveMQ", Source: "https://activemq.apache.org/web-console",
		// Ports: 8161: https://activemq.apache.org/web-console; 61616: https://activemq.apache.org/components/classic/documentation/version-5-getting-started
		Ports: []int{8161, 61616},
		User:  "admin", Pass: "admin", Mode: ModeBasic, Path: "/admin/queues.jsp", // /admin/ itself can be public: a page that answers 200 to all proves no password
		Success: basicMarker("queues", "activemq"),
	},
	{
		ID: "harbor-admin-harbor12345", Product: "Harbor", Source: "https://goharbor.io/docs/main/install-config/configure-yml-file/",
		// Ports: https://goharbor.io/docs/main/install-config/configure-yml-file/ (http, https)
		Ports: []int{80, 443},
		User:  "admin", Pass: "Harbor12345", Mode: ModeBasic, Path: "/api/v2.0/users/current",
		Success: basicMarker("username", "sysadmin_flag", "\"admin\""),
	},
	{
		ID: "artifactory-admin-password", Product: "Artifactory", Source: "https://docs.jfrog.com/administration/docs/manage-users-2",
		// Ports: https://docs.jfrog.com/installation/docs/network-requirements-for-jfrog-products
		Ports: []int{8081, 8082},
		User:  "admin", Pass: "password", Mode: ModeBasic, Path: "/artifactory/api/security/users",
		Success: basicMarker("\"name\"", "\"uri\""),
	},
	{
		ID: "neo4j-neo4j-neo4j", Product: "Neo4j", Source: "https://neo4j.com/docs/operations-manual/current/configuration/set-initial-password/",
		// Ports: https://neo4j.com/docs/operations-manual/current/configuration/ports/
		Ports: []int{7474, 7473, 7687},
		User:  "neo4j", Pass: "neo4j", Mode: ModeBasic, Path: "/user/neo4j", // gated, https://neo4j.com/docs/2.3.2/rest-api-security.html; / is public
		Success: basicMarker("password_change_required"),
	},
	{
		ID: "grafana-admin-admin", Product: "Grafana", Source: "https://grafana.com/docs/grafana/latest/setup-grafana/sign-in-to-grafana/",
		// Ports: the Source page: "http://localhost:3000 by default"
		Ports: []int{3000},
		User:  "admin", Pass: "admin", Mode: ModeBasic, Path: "/api/org",
		Success: basicMarker("\"name\""),
	},
	{
		ID: "sonarqube-admin-admin", Product: "SonarQube", Source: "https://docs.sonarsource.com/sonarqube-server/latest/try-out-sonarqube/",
		// Ports: the Source page: http://localhost:9000
		Ports: []int{9000},
		User:  "admin", Pass: "admin", Mode: ModeBasic, Path: "/api/authentication/validate",
		Success: basicMarker("\"valid\":true"),
	},
	{
		ID: "ambari-admin-admin", Product: "Ambari", Source: "https://ambari.apache.org/docs/3.0.0/quick-start/installation-guide/",
		// Ports: the Source page: step 7, port 8080
		Ports: []int{8080},
		User:  "admin", Pass: "admin", Mode: ModeBasic, Path: "/api/v1/clusters",
		Success: basicMarker("\"items\""),
	},
	{
		ID: "mongo-express-admin-pass", Product: "mongo-express", Source: "https://github.com/mongo-express/mongo-express",
		// Ports: the Source page (README): default 8081
		Ports: []int{8081},
		User:  "admin", Pass: "pass", Mode: ModeBasic, Path: "/",
		Success: basicMarker("mongo express", "mongo-express"),
	},
	{
		ID: "mikrotik-admin-blank", Product: "MikroTik RouterOS", Source: "https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management",
		// Ports: the www and www-ssl services; the REST API page https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API names them but not their ports
		Ports: []int{80, 443},
		User:  "admin", Pass: "", Mode: ModeBasic, Path: "/rest/system/identity",
		Success: basicMarker("\"name\""),
	},
	{
		ID: "wazuh-indexer-admin-admin", Product: "Wazuh", Source: "https://documentation.wazuh.com/4.6/installation-guide/wazuh-dashboard/step-by-step.html",
		// Ports: https://documentation.wazuh.com/current/getting-started/architecture.html (required ports)
		Ports: []int{9200, 55000, 443, 1514, 1515},
		User:  "admin", Pass: "admin", Mode: ModeBasic, Path: "/",
		Success: basicMarker("cluster_name", "cluster_uuid"),
	},
	{
		ID: "emqx-admin-public", Product: "EMQX", Source: "https://docs.emqx.com/en/emqx/latest/dashboard/introduction.html",
		// Ports: the Source page: dashboard listens on 18083
		Ports: []int{18083},
		User:  "admin", Pass: "public", Mode: ModeJSON, Path: "/api/v5/login",
		Body: func(user, pass string) []byte {
			return []byte(fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass))
		},
		Success: func(status int, body []byte) bool { return status == 200 && bodyHasAny(body, []string{"\"token\""}) },
	},
	{
		ID: "zabbix-admin-zabbix", Product: "Zabbix", Source: "https://www.zabbix.com/documentation/7.4/en/manual/installation/frontend",
		// Ports: 10051: https://www.zabbix.com/documentation/current/en/manual/appendix/config/zabbix_server (ListenPort); the frontend is a web page on 80 or 443
		Ports: []int{80, 443, 10051},
		User:  "Admin", Pass: "zabbix", Mode: ModeJSON, Path: "/api_jsonrpc.php",
		Body: func(user, pass string) []byte {
			return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","method":"user.login","params":{"username":%q,"password":%q},"id":1}`, user, pass))
		},
		Success: func(status int, body []byte) bool {
			return status == 200 && bodyHasAny(body, []string{"\"result\""}) && !bodyHasAny(body, []string{"\"error\""})
		},
	},
	{
		ID: "pfsense-admin-pfsense", Product: "pfSense", Source: "https://docs.netgate.com/pfsense/en/latest/usermanager/defaults.html",
		// Ports: https://docs.netgate.com/pfsense/en/latest/config/advanced-admin.html (HTTPS on 443, port 80 redirects)
		Ports: []int{443, 80},
		User:  "admin", Pass: "pfsense", Mode: ModeForm, Path: "/index.php",
		UserField: "usernamefld", PassField: "passwordfld", CaptchaCheck: true,
		Success: func(status int, body []byte) bool {
			return status == 200 && bodyHasAny(body, []string{"widget-row", "dashboard-container"}) && !bodyHasAny(body, []string{"username or password"})
		},
		Logout: func(ctx context.Context, d HTTPDoer, origin, cookie string, body []byte) {
			logoutGET(ctx, d, origin+"/index.php?logout", cookie)
		},
	},
	{
		ID: "rundeck-admin-admin", Product: "Rundeck", Source: "https://docs.rundeck.com/docs/administration/security/default-users.html",
		// Ports: https://docs.rundeck.com/docs/administration/install/linux-deb.html (listens on 4440)
		Ports: []int{4440},
		User:  "admin", Pass: "admin", Mode: ModeForm, Path: "/j_security_check",
		UserField: "j_username", PassField: "j_password",
		Success: func(status int, body []byte) bool {
			return status == 302 || (status == 200 && bodyHasAny(body, []string{"rundeck"}))
		},
		Logout: func(ctx context.Context, d HTTPDoer, origin, cookie string, body []byte) {
			logoutGET(ctx, d, origin+"/logout", cookie)
		},
	},
	{
		ID: "guacamole-guacadmin-guacadmin", Product: "Apache Guacamole", Source: "https://apache.googlesource.com/guacamole-client/+/276f8d4f0fa281eb7919ff6d8e565e477ca851a6/extensions/guacamole-auth-jdbc/modules/guacamole-auth-jdbc-mysql/schema/002-create-admin-user.sql",
		// Ports: https://guacamole.apache.org/doc/gug/guacamole-docker.html (web app 8080, guacd 4822)
		Ports: []int{8080, 4822},
		User:  "guacadmin", Pass: "guacadmin", Mode: ModeForm, Path: "/guacamole/api/tokens",
		UserField: "username", PassField: "password",
		Success: func(status int, body []byte) bool {
			return status == 200 && bodyHasAny(body, []string{"\"authtoken\""})
		},
	},
	{
		ID: "opennms-admin-admin", Product: "OpenNMS", Source: "https://docs.opennms.com/horizon/36/deployment/core/install.html",
		// Ports: the Source page: web application on 8980
		Ports: []int{8980},
		User:  "admin", Pass: "admin", Mode: ModeForm, Path: "/opennms/j_spring_security_check",
		UserField: "j_username", PassField: "j_password",
		Success: func(status int, body []byte) bool {
			return status == 302 || (status == 200 && bodyHasAny(body, []string{"opennms"}))
		},
		Logout: func(ctx context.Context, d HTTPDoer, origin, cookie string, body []byte) {
			logoutGET(ctx, d, origin+"/opennms/j_spring_security_logout", cookie)
		},
	},
	{
		ID: "dolphinscheduler-admin-dolphinscheduler123", Product: "Apache DolphinScheduler",
		// Ports: the UI port of https://dolphinscheduler.apache.org/en-us/docs/latest/guide/start/quick-start
		Ports:  []int{12345},
		Source: "https://apache.googlesource.com/dolphinscheduler-website/+show/1a7cac94f5a521a83abfd16949c2206faee8812d/docs/en-us/dev/user_doc/guide/quick-start.md",
		User:   "admin", Pass: "dolphinscheduler123", Mode: ModeForm, Path: "/dolphinscheduler/login",
		UserField: "userName", PassField: "userPassword",
		Success: func(status int, body []byte) bool { return status == 200 && bodyHasAny(body, []string{"\"code\":0"}) },
	},
	{
		ID: "showdoc-default-account", Product: "ShowDoc", Source: "https://github.com/star7th/showdoc/blob/master/documentation/en/AutoInstall.md",
		// Ports: the Source page: "http://your-domain.com:4999"
		Ports: []int{4999},
		// The sign-in is /api/user/login of its server (UserController::login): "no empty password" to the
		// no-credential control, a wrong-pair error to the other, user_token only for a pair it accepts.
		User: "showdoc", Pass: "123456", Mode: ModeForm, Path: "/server/index.php?s=/api/user/login",
		UserField: "username", PassField: "password",
		Success: func(status int, body []byte) bool {
			return status == 200 && bodyHasAny(body, []string{"\"user_token\""})
		},
		Logout: func(ctx context.Context, d HTTPDoer, origin, cookie string, body []byte) {
			logoutPOST(ctx, d, origin+"/server/index.php?s=/api/user/logout", cookie, "confirm=1")
		},
	},
}

// logoutPOST is logoutGET for a product that ends a session with a POST.
func logoutPOST(ctx context.Context, d HTTPDoer, url, cookie, form string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(form))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	_, _, _ = d.do(ctx, req)
}

// logoutGET is the best-effort GET of url with cookie set, through d so it
// is counted and ledgered: it ends a session this check made.
func logoutGET(ctx context.Context, d HTTPDoer, url, cookie string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	_, _, _ = d.do(ctx, req)
}

func bodyMarker(markers ...string) func(status int, body []byte) bool {
	return func(status int, body []byte) bool { return bodyHasAny(body, markers) }
}

// The windows of OpenTSDB's evidence: the one key (or metric) that was matched
// and its value.
var (
	openTSDBPort = lazyre.New(`"tsd\.network\.port"\s*:\s*"[^"]*"`)
	openTSDBStat = lazyre.New(`"metric"\s*:\s*"tsd\.connectionmgr\.[^"]*"`)
)

var unauthReads = []UnauthRead{
	{
		ID: "spark-master-ui", Product: "Apache Spark", Path: "/",
		// Ports: https://spark.apache.org/docs/latest/security.html (Configuring ports for network security)
		Ports:  []int{8080, 7077, 8081, 4040, 18080},
		Source: "https://spark.apache.org/docs/latest/security.html",
		Shown:  bodyMarker("spark master at", "spark standalone cluster"),
	},
	{
		ID: "yarn-resourcemanager-cluster-info", Product: "Hadoop YARN", Path: "/ws/v1/cluster/info",
		// Ports: https://hadoop.apache.org/docs/stable/hadoop-yarn/hadoop-yarn-common/yarn-default.xml (webapp.address, webapp.https.address)
		Ports:  []int{8088, 8090},
		Source: "https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-common/HttpAuthentication.html",
		Shown:  bodyMarker("resourcemanagerversion", "clusterid"),
	},
	{
		ID: "hdfs-webhdfs-liststatus", Product: "Hadoop HDFS", Path: "/webhdfs/v1/?op=LISTSTATUS",
		// Ports: https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-hdfs/hdfs-default.xml (9870, 9871); 50070 of Hadoop 2: https://hadoop.apache.org/docs/r2.10.2/hadoop-project-dist/hadoop-hdfs/hdfs-default.xml
		Ports:  []int{9870, 9871, 50070},
		Source: "https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-hdfs/WebHDFS.html",
		Shown:  bodyMarker("filestatuses"),
	},
	{
		ID: "flink-rest-overview", Product: "Apache Flink", Path: "/overview",
		// Ports: rest.port of https://nightlies.apache.org/flink/flink-docs-stable/docs/deployment/config/
		Ports:  []int{8081},
		Source: "https://flink.apache.org/what-is-flink/security/",
		Shown:  bodyMarker("flink-version", "taskmanagers"),
	},
	{
		ID: "druid-status", Product: "Apache Druid", Path: "/status",
		// Ports: 8081: the Source page (Coordinator); 8888: https://druid.apache.org/docs/latest/tutorials/ (web console)
		Ports:  []int{8081, 8888},
		Source: "https://druid.apache.org/docs/latest/operations/security-overview/",
		Shown:  bodyMarker("\"modules\"", "\"version\""),
	},
	{
		ID: "zookeeper-adminserver-stat", Product: "Apache ZooKeeper", Path: "/commands/stat",
		// Ports: admin.serverPort 8080 and clientPort 2181 on the Source page
		Ports:  []int{8080, 2181},
		Source: "https://zookeeper.apache.org/doc/current/zookeeperAdmin.html",
		Shown:  bodyMarker("zk_version", "zk_server_state"),
	},
	{
		ID: "elasticsearch-cluster-health", Product: "Elasticsearch", Path: "/_cluster/health",
		// Ports: https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html (http.port 9200-9300)
		Ports:  []int{9200},
		Source: "https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-minimal-setup.html",
		Shown:  bodyMarker("cluster_name", "\"status\""),
	},
	{
		ID: "influxdb-show-databases", Product: "InfluxDB", Path: "/query?q=SHOW+DATABASES",
		// Ports: https://docs.influxdata.com/influxdb/v1/administration/config/ (http bind-address :8086)
		Ports:  []int{8086},
		Source: "https://docs.influxdata.com/influxdb/v1/administration/authentication_and_authorization/",
		Shown:  bodyMarker("\"results\""),
	},
	{
		ID: "zeppelin-api-version", Product: "Apache Zeppelin", Path: "/api/version",
		// Ports: https://zeppelin.apache.org/docs/latest/quickstart/install.html (127.0.0.1:8080)
		Ports:  []int{8080},
		Source: "https://zeppelin.apache.org/docs/latest/setup/security/shiro_authentication.html",
		Shown:  bodyMarker("\"version\""),
	},
	{
		ID: "kubernetes-api-version", Product: "Kubernetes", Path: "/version",
		// Ports: https://kubernetes.io/docs/reference/networking/ports-and-protocols/
		Ports:  []int{6443},
		Source: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
		Shown:  bodyMarker("\"gitversion\""),
	},
	{
		ID: "kubelet-pods", Product: "Kubelet", Path: "/pods",
		// Ports: https://kubernetes.io/docs/reference/networking/ports-and-protocols/
		Ports:  []int{10250},
		Source: "https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/",
		Shown:  bodyMarker("\"kind\":\"podlist\""),
	},
	{
		ID: "nats-varz", Product: "NATS", Path: "/varz",
		// Ports: https://docs.nats.io/running-a-nats-service/configuration/monitoring (8222 monitoring, 4222 client)
		Ports:  []int{4222, 8222},
		Source: "https://docs.nats.io/running-a-nats-service/configuration/monitoring",
		Shown:  bodyMarker("\"server_id\""),
	},
	{
		ID: "etcd-health", Product: "etcd", Path: "/health",
		// Ports: https://etcd.io/docs/v3.5/op-guide/configuration/ (client 2379, peer 2380)
		Ports:  []int{2379, 2380},
		Source: "https://etcd.io/docs/v3.5/op-guide/authentication/rbac/",
		Shown:  bodyMarker("\"health\""),
	},
	{
		ID: "opentsdb-api-config", Product: "OpenTSDB", Path: "/api/config",
		// Ports: the Source pages' example requests: http://localhost:4242
		Ports:  []int{4242},
		Source: "https://opentsdb.net/docs/build/html/api_http/config/index.html",
		Shown: func(status int, body []byte) bool {
			return status == 200 && bodyHasAny(body, []string{"\"tsd.network.port\""})
		},
		Window: func(body []byte) string { return openTSDBPort.FindString(string(body)) },
	},
	{
		ID: "opentsdb-api-stats", Product: "OpenTSDB", Path: "/api/stats",
		Ports:  []int{4242},
		Source: "https://opentsdb.net/docs/build/html/api_http/stats/index.html",
		Shown: func(status int, body []byte) bool {
			return status == 200 && bodyHasAny(body, []string{"\"tsd.connectionmgr."})
		},
		Window: func(body []byte) string { return openTSDBStat.FindString(string(body)) },
	},
}
