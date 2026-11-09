package webextract

import (
	"strings"
	"testing"
)

func TestStackTracePerRuntime(t *testing.T) {
	for _, c := range []struct {
		name, body, runtime, exception string
		frames                         int
	}{
		{"java", "HTTP Status 500\njava.lang.NullPointerException: user is null\n\tat com.shop.UserController.get(UserController.java:42)\n\tat com.shop.Dispatcher.run(Dispatcher.java:10)\n\tat java.base/java.lang.Thread.run(Thread.java:834)\n\tat sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\n",
			"java", "java.lang.NullPointerException: user is null", 4},
		{"java in html", "<html><body><pre>org.h2.jdbc.JdbcSQLException: x<br/>&nbsp;&nbsp;at org.h2.Foo.bar(Foo.java:1)<br/>&nbsp;&nbsp;at org.h2.Foo.baz(Foo.java:2)<br/>&nbsp;&nbsp;at a.B.c(B.kt:3)</pre></body></html>",
			"java", "org.h2.jdbc.JdbcSQLException: x", 3},
		{"python", "Traceback (most recent call last):\n  File \"/app/app.py\", line 12, in index\n    return render(x)\n  File \"/app/render.py\", line 5, in render\n    return 1 / 0\n  File \"/app/m.py\", line 9, in <module>\n    raise\nZeroDivisionError: division by zero\n",
			"python", "ZeroDivisionError: division by zero", 3},
		{"python caret lines", "Traceback (most recent call last):\n  File \"a.py\", line 1, in a\n    b()\n    ~^^\n  File \"b.py\", line 2, in b\n    c()\n    ~^^\n  File \"c.py\", line 3, in c\n    1/0\n    ~^^\nValueError: bad\n",
			"python", "ValueError: bad", 3},
		{"python in json", `{"trace":"Traceback (most recent call last):\n  File \"a.py\", line 1, in a\n    b()\n  File \"b.py\", line 2, in b\n    c()\n  File \"c.py\", line 3, in c\n    1/0\nKeyError: 'id'\n"}`,
			"python", "KeyError: 'id'", 3},
		{"node", "<pre>TypeError: Cannot read properties of undefined (reading 'id')<br> &nbsp; &nbsp;at Object.handler (/app/routes/user.js:12:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/app/node_modules/express/lib/router/route.js:144:13)<br> &nbsp; &nbsp;at /app/x.js:1:2</pre>",
			"node", "TypeError: Cannot read properties of undefined (reading 'id')", 4},
		{"php", "PHP Fatal error:  Uncaught Exception: boom in /var/www/a.php:3\nStack trace:\n#0 /var/www/a.php(7): f()\n#1 /var/www/index.php(2): g()\n#2 {main}\n  thrown in /var/www/a.php on line 3\n",
			"php", "PHP Fatal error: Uncaught Exception: boom in /var/www/a.php:3", 3},
		{"dotnet", "System.NullReferenceException: Object reference not set\n   at Shop.Cart.Total() in C:\\src\\Cart.cs:line 40\n   at Shop.Pages.Index.Load(Object s, EventArgs e) in C:\\src\\Index.cs:line 12\n   at System.Web.UI.Control.OnLoad(EventArgs e) in c:\\x\\Control.cs:line 9\n",
			"dotnet", "System.NullReferenceException: Object reference not set", 3},
		{"ruby", "app/models/user.rb:12:in `name': undefined method (NoMethodError)\n\tfrom app/models/user.rb:20:in `each'\n\tfrom app/controllers/users_controller.rb:5:in `index'\n\tfrom /gems/rack.rb:9:in `call'\n",
			"ruby", "", 3},
	} {
		got, ok := StackTrace([]byte(c.body))
		if !ok || got.Runtime != c.runtime || got.Frames != c.frames || (c.exception != "" && got.Exception != c.exception) {
			t.Errorf("%s: %+v %v, want %s with %d frames, exception %q", c.name, got, ok, c.runtime, c.frames, c.exception)
		}
		if got.Exception == "" && ok {
			t.Errorf("%s: no exception line", c.name)
		}
	}
}

func TestStackTraceNeedsThreeConsecutiveFrames(t *testing.T) {
	long := strings.Repeat("The page <b>about</b> errors. ", 50)
	for name, body := range map[string]string{
		"prose":             "<p>A Java stack trace lists frames such as at com.shop.UserController.get(UserController.java:42) and at com.shop.Dispatcher.run(Dispatcher.java:10) and at a.B.c(B.java:3), one per line.</p>",
		"prose python":      `<p>Python prints File "app.py", line 3, in main for each frame, then File "b.py", line 4, in f, then File "c.py", line 5, in g.</p>`,
		"two frames":        "NullPointerException\n\tat a.B.c(B.java:1)\n\tat a.B.d(B.java:2)\n",
		"frames apart":      "at a.B.c(B.java:1)\nsome text\nat a.B.d(B.java:2)\nmore text\nat a.B.e(B.java:3)\n",
		"mixed runtimes":    "at a.B.c(B.java:1)\nat x (f.js:1:2)\nFile \"a.py\", line 1\n",
		"a script":          "<script src=\"/app.js:1\"></script>" + long,
		"markdown headings": "#1 Intro\n#2 Setup\n#3 Usage (page 4): see below\n",
		"empty":             "",
	} {
		if got, ok := StackTrace([]byte(body)); ok {
			t.Errorf("%s: found %+v", name, got)
		}
	}
}
