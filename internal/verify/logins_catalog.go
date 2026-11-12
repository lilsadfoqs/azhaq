package verify

import (
	"context"
	"fmt"
	"net/http"
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
		User: "guest", Pass: "guest", Mode: ModeBasic, Path: "/api/overview",
		Success: basicMarker("rabbitmq_version", "management_version"),
	},
	{
		ID: "activemq-admin-admin", Product: "ActiveMQ", Source: "https://activemq.apache.org/web-console",
		User: "admin", Pass: "admin", Mode: ModeBasic, Path: "/admin/",
		Success: basicMarker("activemq", "<html"),
	},
	{
		ID: "harbor-admin-harbor12345", Product: "Harbor", Source: "https://goharbor.io/docs/main/install-config/configure-yml-file/",
		User: "admin", Pass: "Harbor12345", Mode: ModeBasic, Path: "/api/v2.0/users/current",
		Success: basicMarker("username", "sysadmin_flag", "\"admin\""),
	},
	{
		ID: "artifactory-admin-password", Product: "Artifactory", Source: "https://docs.jfrog.com/administration/docs/manage-users-2",
		User: "admin", Pass: "password", Mode: ModeBasic, Path: "/artifactory/api/security/users",
		Success: basicMarker("\"name\"", "\"uri\""),
	},
	{
		ID: "neo4j-neo4j-neo4j", Product: "Neo4j", Source: "https://neo4j.com/docs/operations-manual/current/configuration/set-initial-password/",
		User: "neo4j", Pass: "neo4j", Mode: ModeBasic, Path: "/",
		Success: basicMarker("neo4j_version", "bolt_routing", "\"bolt\""),
	},
	{
		ID: "grafana-admin-admin", Product: "Grafana", Source: "https://grafana.com/docs/grafana/latest/setup-grafana/sign-in-to-grafana/",
		User: "admin", Pass: "admin", Mode: ModeBasic, Path: "/api/org",
		Success: basicMarker("\"name\""),
	},
	{
		ID: "sonarqube-admin-admin", Product: "SonarQube", Source: "https://docs.sonarsource.com/sonarqube-server/latest/try-out-sonarqube/",
		User: "admin", Pass: "admin", Mode: ModeBasic, Path: "/api/authentication/validate",
		Success: basicMarker("\"valid\":true"),
	},
	{
		ID: "ambari-admin-admin", Product: "Ambari", Source: "https://ambari.apache.org/docs/3.0.0/quick-start/installation-guide/",
		User: "admin", Pass: "admin", Mode: ModeBasic, Path: "/api/v1/clusters",
		Success: basicMarker("\"items\""),
	},
	{
		ID: "mongo-express-admin-pass", Product: "mongo-express", Source: "https://github.com/mongo-express/mongo-express",
		User: "admin", Pass: "pass", Mode: ModeBasic, Path: "/",
		Success: basicMarker("mongo express", "mongo-express"),
	},
	{
		ID: "mikrotik-admin-blank", Product: "MikroTik RouterOS", Source: "https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management",
		User: "admin", Pass: "", Mode: ModeBasic, Path: "/rest/system/identity",
		Success: basicMarker("\"name\""),
	},
	{
		ID: "wazuh-indexer-admin-admin", Product: "Wazuh", Source: "https://documentation.wazuh.com/4.6/installation-guide/wazuh-dashboard/step-by-step.html",
		User: "admin", Pass: "admin", Mode: ModeBasic, Path: "/",
		Success: basicMarker("cluster_name", "cluster_uuid"),
	},
	{
		ID: "emqx-admin-public", Product: "EMQX", Source: "https://docs.emqx.com/en/emqx/latest/dashboard/introduction.html",
		User: "admin", Pass: "public", Mode: ModeJSON, Path: "/api/v5/login",
		Body: func(user, pass string) []byte {
			return []byte(fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass))
		},
		Success: func(status int, body []byte) bool { return status == 200 && bodyHasAny(body, []string{"\"token\""}) },
	},
	{
		ID: "zabbix-admin-zabbix", Product: "Zabbix", Source: "https://www.zabbix.com/documentation/7.4/en/manual/installation/frontend",
		User: "Admin", Pass: "zabbix", Mode: ModeJSON, Path: "/api_jsonrpc.php",
		Body: func(user, pass string) []byte {
			return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","method":"user.login","params":{"username":%q,"password":%q},"id":1}`, user, pass))
		},
		Success: func(status int, body []byte) bool {
			return status == 200 && bodyHasAny(body, []string{"\"result\""}) && !bodyHasAny(body, []string{"\"error\""})
		},
	},
	{
		ID: "pfsense-admin-pfsense", Product: "pfSense", Source: "https://docs.netgate.com/pfsense/en/latest/usermanager/defaults.html",
		User: "admin", Pass: "pfsense", Mode: ModeForm, Path: "/index.php",
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
		User: "admin", Pass: "admin", Mode: ModeForm, Path: "/j_security_check",
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
		User: "guacadmin", Pass: "guacadmin", Mode: ModeForm, Path: "/guacamole/api/tokens",
		UserField: "username", PassField: "password",
		Success: func(status int, body []byte) bool {
			return status == 200 && bodyHasAny(body, []string{"\"authtoken\""})
		},
	},
	{
		ID: "opennms-admin-admin", Product: "OpenNMS", Source: "https://docs.opennms.com/horizon/36/deployment/core/install.html",
		User: "admin", Pass: "admin", Mode: ModeForm, Path: "/opennms/j_spring_security_check",
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
		Source: "https://apache.googlesource.com/dolphinscheduler-website/+show/1a7cac94f5a521a83abfd16949c2206faee8812d/docs/en-us/dev/user_doc/guide/quick-start.md",
		User:   "admin", Pass: "dolphinscheduler123", Mode: ModeForm, Path: "/dolphinscheduler/login",
		UserField: "userName", PassField: "userPassword",
		Success: func(status int, body []byte) bool { return status == 200 && bodyHasAny(body, []string{"\"code\":0"}) },
	},
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

var unauthReads = []UnauthRead{
	{
		ID: "spark-master-ui", Product: "Apache Spark", Path: "/",
		Source: "https://spark.apache.org/docs/latest/security.html",
		Shown:  bodyMarker("spark master at", "spark standalone cluster"),
	},
	{
		ID: "yarn-resourcemanager-cluster-info", Product: "Hadoop YARN", Path: "/ws/v1/cluster/info",
		Source: "https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-common/HttpAuthentication.html",
		Shown:  bodyMarker("resourcemanagerversion", "clusterid"),
	},
	{
		ID: "hdfs-webhdfs-liststatus", Product: "Hadoop HDFS", Path: "/webhdfs/v1/?op=LISTSTATUS",
		Source: "https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-hdfs/WebHDFS.html",
		Shown:  bodyMarker("filestatuses"),
	},
	{
		ID: "flink-rest-overview", Product: "Apache Flink", Path: "/overview",
		Source: "https://flink.apache.org/what-is-flink/security/",
		Shown:  bodyMarker("flink-version", "taskmanagers"),
	},
	{
		ID: "druid-status", Product: "Apache Druid", Path: "/status",
		Source: "https://druid.apache.org/docs/latest/operations/security-overview/",
		Shown:  bodyMarker("\"modules\"", "\"version\""),
	},
	{
		ID: "zookeeper-adminserver-stat", Product: "Apache ZooKeeper", Path: "/commands/stat",
		Source: "https://zookeeper.apache.org/doc/current/zookeeperAdmin.html",
		Shown:  bodyMarker("zk_version", "zk_server_state"),
	},
	{
		ID: "elasticsearch-cluster-health", Product: "Elasticsearch", Path: "/_cluster/health",
		Source: "https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-minimal-setup.html",
		Shown:  bodyMarker("cluster_name", "\"status\""),
	},
	{
		ID: "influxdb-show-databases", Product: "InfluxDB", Path: "/query?q=SHOW+DATABASES",
		Source: "https://docs.influxdata.com/influxdb/v1/administration/authentication_and_authorization/",
		Shown:  bodyMarker("\"results\""),
	},
	{
		ID: "zeppelin-api-version", Product: "Apache Zeppelin", Path: "/api/version",
		Source: "https://zeppelin.apache.org/docs/latest/setup/security/shiro_authentication.html",
		Shown:  bodyMarker("\"version\""),
	},
	{
		ID: "kubernetes-api-version", Product: "Kubernetes", Path: "/version",
		Source: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
		Shown:  bodyMarker("\"gitversion\""),
	},
	{
		ID: "kubelet-pods", Product: "Kubelet", Path: "/pods",
		Source: "https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/",
		Shown:  bodyMarker("\"kind\":\"podlist\""),
	},
	{
		ID: "nats-varz", Product: "NATS", Path: "/varz",
		Source: "https://docs.nats.io/running-a-nats-service/configuration/monitoring",
		Shown:  bodyMarker("\"server_id\""),
	},
	{
		ID: "etcd-health", Product: "etcd", Path: "/health",
		Source: "https://etcd.io/docs/v3.5/op-guide/authentication/rbac/",
		Shown:  bodyMarker("\"health\""),
	},
}
