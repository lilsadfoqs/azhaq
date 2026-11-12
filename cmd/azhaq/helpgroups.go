package main

// helpGroup is one task heading of a command's help and flag table, with
// the names of the flags under it, in the order they print.
type helpGroup struct {
	title string // "" for a command whose flags need no headings
	flags string // space-separated flag names
}

// helpSpec is how one command's flags show: the groups of the flags -h
// prints, and the flags it leaves for -h all, each with its reason.
type helpSpec struct {
	groups []helpGroup
	hidden map[string]string // reason -> space-separated flag names
}

// planOnly are the flags plan has and run has not, shown after run's table.
var planOnly = helpGroup{"Plan only", `axfr`}

// The one table behind every command's -h, -h all, help -json and flag table
// of its docs page: each flag is in a task group (shown) or hidden for a
// reason, never both, and a test holds the table to the real flags.
//
// A hidden flag's reason is compat:TOOL (that tool's name for it, kept so its
// command lines run), alias (another name of a flag), accepted (read for a
// tool's command lines, no effect of its own) or rare (kept, rarely needed).
// plan takes run's entry, with planOnly after it.
var helpSpecs = map[string]helpSpec{
	"run": {
		groups: []helpGroup{
			{"Targets and input", `url domain list in asn cidr org scope program exec demo`},
			{"What to ask", `probe passive skip dirs params ports ports-on ports-udp dns-brute permute no-vhost no-takeover graphql graphql-wordlist known-files paths no-paths path-climb fill-forms per-template catchall-after web-ports web-scheme no-favicon no-tech no-map-guess no-follow advisories advisories-confirm advisory-source verify verify-logins`},
			{"Crawl scope", `crawl-scope crawl-any-host crawl-in crawl-out`},
			{"Names and sources", `sources all-sources exclude-sources providers resolvers dns-rate source-proxy source-rate source-rates source-timeout extra-wait max-time max-body max-results urls-timeout no-history history-dir`},
			{"Browser", `browser interact interact-clicks screenshots chrome chrome-profile chrome-proxy chrome-no-sandbox chrome-require-sandbox tabs unsafe-ports`},
			{"Scope and safety", `allow sweep deny deny-path send-state-changing kill-file ledger seal-to submit-forms browser-writes params-writes`},
			{"Pace and limits", `rate host-rate host-parallel parallel delay backoff retry request-timeout timeout max-requests max-host-requests host-guesses daily-requests max-items max-names max-ips max-response-size depth retry-failed retry-run`},
			{"Session", `cookie cookie-jar header login login-user login-pass proxy`},
			{"Output", `db json o quiet v stream sr srd no-catchall all-rows fail-on-errors fail-on-capped strict-exit`},
		},
		hidden: map[string]string{
			"alias":    `H`,
			"accepted": `port-cdn-full`,
			"rare": `
				ob
				port-exclude-cdn serve worker-token dirs-ac dirs-depth dirs-ext dirs-ic dirs-fc dirs-fl dirs-fr dirs-fs dirs-fw dirs-mc dirs-ml dirs-mr dirs-ms
				dirs-mw dirs-rate dirs-threads facts obs params-chunk params-delay params-include params-method
				params-all params-per-host params-rate params-stable params-targets params-threads params-timeout
				port-all-ips port-detect port-discover port-ip port-min-rate port-order port-payload port-proxy
				port-proxy-auth port-rate port-retries port-seed port-skip port-source-ip port-threshold port-timeout
				port-unnamed port-workers shot-codes shot-format shot-fullpage shot-html shot-js shot-quality
				shot-size shot-timeout shot-wait urls urls-archive urls-blacklist urls-fc urls-fp urls-from
				urls-ft urls-keep-junk urls-max urls-mc urls-mt urls-pages urls-pause urls-proxy urls-raw urls-retries
				urls-source urls-sources urls-subs urls-to
			`,
		},
	},
	"scope": {
		groups: []helpGroup{
			{"", `scope program json`},
		},
	},
	"roles": {
		groups: []helpGroup{
			{"Sessions", `role role-cmd role-login login har burp no-anon canary canary-every`},
			{"What to replay", `replay replay-max replay-writes replay-writes-canary replay-writes-field replay-writes-verify dry-writes id refusal allow all`},
			{"Scope and safety", `deny deny-path seal-to`},
			{"Pace and network", `rate proxy resolvers`},
			{"Output", `dir json plan`},
		},
		hidden: map[string]string{
			"alias": `
				jsonl
			`,
		},
	},
	"report": {
		groups: []helpGroup{
			{"", `findings db dir url method owner format o redact`},
		},
	},
	"subs": {
		groups: []helpGroup{
			{"Targets and input", `d dL`},
			{"What to ask", `live http guesses guess-samples w permute all-sources sources m providers fresh`},
			{"Pace and limits", `source-rate source-rates source-timeout extra-wait max-time max-body max-results max-names dns-rate t timeout`},
			{"Scope and safety", `allow deny scope program seal-to`},
			{"Network", `resolvers proxy web-ports http-proxy`},
			{"Output", `db ledger json o oI silent v fail-on-errors ls stats no-history history-dir strict-exit`},
		},
		hidden: map[string]string{
			"compat:subfinder": `
				cs exclude-sources f filter-regex match-regex oD recursive version
			`,
			"alias": `
				nW oJ
			`,
			"accepted": `
				ei
			`,
		},
	},
	"dns": {
		groups: []helpGroup{
			{"Targets and input", `d l w start`},
			{"Record types", `a aaaa cname ns txt srv ptr mx soa caa any axfr all e`},
			{"What to ask", `no-wildcard no-takeover`},
			{"Answer format and filters", `resp resp-only rcode response-type-filter`},
			{"Scope and safety", `allow deny scope program ledger seal-to`},
			{"Pace and limits", `rl t dns-rate retry timeout maxtime`},
			{"Network", `resolvers proxy`},
			{"Output", `db json o silent v strict-exit`},
		},
		hidden: map[string]string{
			"compat:dnsx": `
				asn cdn health-check hostsfile omit-raw output-template raw stats stream trace
				trace-max-recursion wildcard-domain
			`,
			"alias": `
				aw debug disable-update-check hc hf j or ot r rate-limit rc re recon ro rtf threads wd wt
			`,
			"accepted": `
				auto-wildcard duc nc wildcard-threshold
			`,
		},
	},
	"probe": {
		groups: []helpGroup{
			{"Targets and input", `u l p scope program max-ips no-stdin`},
			{"What to ask", `path x body probe fr no-follow no-tech tls-grab hash jarm`},
			{"Matchers and filters", `mc ms mdc fc`},
			{"Output fields", `sc title td ip location`},
			{"Raw responses", `sr srd irh irr debug-req`},
			{"Scope and safety", `allow deny deny-path kill-file ledger seal-to`},
			{"Pace and limits", `rate rl delay host-parallel parallel dns-rate req-timeout timeout max-requests`},
			{"Session and network", `H cookie proxy resolvers`},
			{"Output", `db json o silent v strict-exit`},
		},
		hidden: map[string]string{
			"compat:httpx": `
				asn auto-referer body-preview cdn cname content-length content-type cpe csp-probe csv
				csv-output-encoding custom-fingerprint-file debug debug-resp exclude exclude-output-fields
				extract-fqdn extract-preset extract-regex favicon filter-cdn filter-condition filter-duplicates
				filter-error-page filter-favicon filter-length filter-line-count filter-page-type filter-regex
				filter-response-time filter-string filter-word-count follow-host-redirects http2 include-chain
				include-response-base64 input-mode j knowledge-base leave-default-ports line-count
				list-dsl-variables markdown match-cdn match-favicon match-length match-line-count match-regex
				match-response-time match-word-count max-host-error max-redirects maxhr method no-decode
				no-fallback omit-body output-all pipeline probe-all-ips random-agent request respect-hsts
				response-size-to-read response-size-to-save response-time retries rlm screenshot sni-name
				store-chain strip target tls-probe vhost vhost-input web-server websocket word-count wordpress
			`,
			"alias": `
				bp cff cl csvo ct e efqdn eof ep er fcdn fd fdc fe fep ffc fhr filter-code fl flc
				follow-redirects fpt frt fs fwc http-proxy im include-response include-response-header irrb kb
				lc ldp ldv list-output-fields lof match-code match-condition match-string maxr mcdn md mfc ml
				mlc mr mrt mwc nf oa ob pa ports rate-limit rhsts rr rstr rsts rt server sni ss status-code
				store-response store-response-dir t tech-detect vi wc web-ports wp header
			`,
			"accepted": `
				nc
			`,
		},
	},
	"crawl": {
		groups: []helpGroup{
			{"Targets and input", `u l scope program`},
			{"What to ask", `d paths builtin-paths no-form-fill per-template no-follow no-map-guess browser interact interact-clicks fs kf`},
			{"What to list", `assets hints no-catchall all-rows rejected em ndef do`},
			{"Scope and safety", `allow sweep deny deny-path send-state-changing kill-file ledger submit-forms browser-writes chrome-no-sandbox seal-to`},
			{"Pace and limits", `rl delay backoff retry host-rate hrl host-parallel parallel request-timeout ct max-requests max-host-requests host-guesses max-items max-response-size`},
			{"Session and network", `H cookie cookie-jar login login-user login-pass proxy resolvers`},
			{"Output", `db o json jsonl f ot silent v strict-exit`},
		},
		hidden: map[string]string{
			"compat:katana": `
				cos cs depth ef eof fr hrlm iqp lof mdp mr mrs ns ob path-climb rd rlm sf sfd sr srd
			`,
			"alias": `
				c dr j p pc r rate timeout header
			`,
			"accepted": `
				jsl duc fx jc kb nc s td
			`,
		},
	},
	"urls": {
		groups: []helpGroup{
			{"Targets and input", `d dL`},
			{"What to ask", `providers provider-config archive raw subs keep-junk`},
			{"Matchers and filters", `mc mt ft blacklist fp from to`},
			{"Spot-check the live site", `live live-rate live-max live-proxy send-state-changing`},
			{"Pace and limits", `urls-max urls-pages urls-pause urls-threads urls-timeout retries timeout rate max-requests`},
			{"Scope and safety", `allow deny scope program ledger seal-to deny-path`},
			{"Network", `proxy resolvers`},
			{"Output", `db o json silent v sort stream fail-on-capped fail-on-errors strict-exit`},
		},
		hidden: map[string]string{
			"compat:gau": `
				config fc version
			`,
			"alias": `
				threads
			`,
		},
	},
	"ports": {
		groups: []helpGroup{
			{"Targets and input", `host l p tp ep no-stdin scope program`},
			{"What to ask", `udp pu detect order unnamed exclude-cdn seed sn wn advisories advisories-confirm advisory-source verify verify-logins`},
			{"Scope and safety", `allow sweep deny kill-file ledger seal-to`},
			{"Pace and limits", `rate min-rate workers connect-timeout dns-rate retries max-requests timeout`},
			{"Network", `proxy resolvers`},
			{"Output", `db json o oA oX silent udp-rows v`},
		},
		hidden: map[string]string{
			"compat:naabu": `
				T cp csv ef eh eof iv lof oG pf proxy-auth pts sa source-ip
			`,
			"alias": `
				ec c j max-retries r
			`,
			"accepted": `
				cdn-full Pn cdn nc
			`,
		},
	},
	"dirs": {
		groups: []helpGroup{
			{"Targets and input", `u l scope program`},
			{"What to ask", `w ic e depth ac`},
			{"Matchers and filters", `mc fc fs`},
			{"Scope and safety", `allow deny deny-path send-state-changing kill-file ledger seal-to`},
			{"Pace and limits", `rate t max-requests timeout`},
			{"Session and network", `H cookie proxy resolvers`},
			{"Output", `db json o silent v strict-exit`},
		},
		hidden: map[string]string{
			"alias": `header`,
			"compat:ffuf": `
				fl fr fw ml mr ms mw
			`,
		},
	},
	"fuzz": {
		groups: []helpGroup{
			{"Targets and input", `u w start scope program`},
			{"What to ask", `mode e recursion recursion-depth`},
			{"Matchers and filters", `mc mr fc fs fl fw ac`},
			{"The request", `X d H r request request-proto`},
			{"Before and after each request", `preflight preflight-mode preflight-error preflight-var preflight-var-auto postflight postflight-var postflight-var-auto`},
			{"Scope and safety", `allow deny deny-path send-state-changing kill-file ledger seal-to`},
			{"Pace and limits", `rate t p timeout maxtime max-requests se-after control`},
			{"Session and network", `x proxy replay-proxy resolvers`},
			{"Output", `db json o of silent quiet v c strict-exit`},
		},
		hidden: map[string]string{
			"compat:ffuf": `
				D V acc ach ack acs b cc ck config data-binary debug-log enc fmode fr ft http2 ic ignore-body
				input-cmd input-num input-shell maxtime-job ml mmode ms mt mw od or raw recursion-strategy sa se
				sf sni
			`,
			"alias": `
				s cookie data data-ascii header
			`,
			"accepted": `
				noninteractive
			`,
		},
	},
	"params": {
		groups: []helpGroup{
			{"Targets and input", `u l i scope program`},
			{"What to ask", `w X c casing passive`},
			{"Scope and safety", `allow deny deny-path send-state-changing kill-file ledger seal-to`},
			{"Pace and limits", `rate t d T max-requests timeout urls-timeout`},
			{"Session and network", `H cookie proxy resolvers`},
			{"Output", `db json o oB oJ oT silent v strict-exit`},
		},
		hidden: map[string]string{
			"alias": `header`,
			"compat:arjun": `
				include stable
			`,
		},
	},
	"asn": {
		groups: []helpGroup{
			{"", `l a db json o silent timeout v`},
		},
	},
	"shots": {
		groups: []helpGroup{
			{"Targets and input", `u l p nmap nessus scope program max-ips`},
			{"Screenshots", `shot-codes shot-format shot-fullpage shot-html shot-js shot-quality shot-size shot-timeout shot-wait no-tech`},
			{"Browser", `chrome chrome-profile chrome-no-sandbox chrome-require-sandbox tabs unsafe-ports`},
			{"Scope and safety", `allow deny deny-path kill-file ledger browser-writes seal-to`},
			{"Pace and limits", `rate max-requests timeout`},
			{"Session and network", `H cookie proxy resolvers`},
			{"Output", `dir csv db json o silent v strict-exit`},
		},
		hidden: map[string]string{
			"alias": `header`,
			"compat:gowitness": `
				chrome-proxy cidr hostnames no-http no-https open-only random service service-contains skip-port
			`,
		},
	},
	"notify": {
		groups: []helpGroup{
			{"", `provider-config proxy delay rate-limit bulk id json silent ledger`},
		},
		hidden: map[string]string{
			"compat:notify": `
				char-limit config data msg-format provider verbose version
			`,
			"alias": `
				cl d duc i mf nc p pc rl v
			`,
			"accepted": `
				disable-update-check no-color
			`,
		},
	},
	"query": {
		groups: []helpGroup{
			{"Which rows", `coverage evidence failed host match method new re role run runs scope since status type`},
			{"Output", `db fields json limit`},
		},
	},
	"show": {
		groups: []helpGroup{
			{"", `db json run`},
		},
	},
	"gallery": {
		groups: []helpGroup{
			{"", `db workspace listen`},
		},
	},
	"runs": {
		groups: []helpGroup{
			{"", `json home limit rm older`},
		},
	},
	"ui": {
		groups: []helpGroup{
			{"", `listen home`},
		},
	},
	"hunt": {
		groups: []helpGroup{
			{"", `db roles limit since json`},
		},
	},
	"watch": {
		groups: []helpGroup{
			{"", `db every always notify notify-cmd notify-config json`},
		},
		hidden: map[string]string{
			"rare": `
				notify-format notify-id notify-lines notify-provider notify-proxy notify-rate
			`,
		},
	},
	"new": {
		groups: []helpGroup{
			{"", `db since json`},
		},
	},
	"diff": {
		groups: []helpGroup{
			{"", `db a b json quiet run`},
		},
		hidden: map[string]string{
			"alias": `jsonl`,
		},
	},
	"export": {
		groups: []helpGroup{
			{"", `db format origin safe coverage json run`},
		},
	},
	"ingest": {
		groups: []helpGroup{
			{"", `in db json`},
		},
	},
	"ledger": {
		groups: []helpGroup{
			{"", `verify seal summary json csv`},
		},
	},
	"mcp": {
		groups: []helpGroup{
			{"Scope and safety", `scope program allow deny deny-path send-state-changing unlocked allow-writes`},
			{"What a map asks", `resolvers sources history skip no-takeover chrome-no-sandbox`},
			{"Pace and limits", `rate max-requests`},
			{"Output", `dir`},
		},
	},
	"worker": {
		groups: []helpGroup{
			{"", `server token slots`},
		},
	},
	"docs": {
		groups: []helpGroup{
			{"", `flags flags-into`},
		},
	},
	"version": {
		groups: []helpGroup{
			{"", `json`},
		},
	},
}
