/**
* Global data structures
 * GLOBAL = {
 *  'randomid': {
 *   'ip': ip,
 *   'port': port
 *  }
*/
var GLOBAL = {};

/**
 * KEY is module name
 * OPTIONS = {
 *  'KEY': {
 *   'value': user decided value,
 *   'modules': [mod1, mod2],
 *  }
 * }
 */
var OPTIONS = {};


var EXPLOITS = {};


// -------------- onlick and onchange functions ------------------- //
function onclick_DNSRebind()	{
	var ip = document.getElementById("exploit_row_ip").value;
	var port = document.getElementById("exploit_row_port").value;
	if(ip != "" && port != "")	{
		perform_dns_rebind(ip, port);
	}
	else	{
		alert("IP and port must be filled out");
	}
}
function get_basic_info()	{
	document.getElementById("browser").innerHTML = Browser()
	document.getElementById("os").innerHTML = OS()
}

function misc_setup()	{
	var a = document.getElementById("deleteme");
	var arr = document.domain.split(".");
	arr.shift();	// Remove first subdomain
	a.href = "http://" + arr.join(".") + "/";
}

function addIPSelect(ip)	{
	var select = document.getElementById("exploit_row_ip");
	var option = document.createElement("option");
	option.value = ip;
	option.innerHTML = ip;
	select.appendChild(option);
	send2log("Added IP " + ip + " to list of options");
}

function network_scan()	{
	var network = document.getElementById("ips2scan").value;
	var iplist = IP.cidr2list(network);
	iplist.shift()
	iplist.pop()
	send2log("Starting IP scan of " + String(iplist.length) + " IPs");
	var scan = Misc.copy_module(PerformIPScan);

	scan.ips2scan = iplist;
	scan.threads = Number(document.getElementById("ipthreads").value);
	scan.shuffle();
	scan.cb_done = cb_ip_scan_done;
	scan.cb_ip_alive = cb_ip_up;
	scan.start_ip_scan();

}
function consent()	{
	var chk = document.getElementById("consentbox");
	var mainblk = document.getElementById("mainblock");
	if(chk.checked == true)	{
		mainblk.style.display = "block";
	}
	else	{
		mainblk.style.display = "none";
	}
}

function getLocalIP()	{
	WebRTC.callback = function(ip)	{
		var el = document.getElementById("localipspan");
		if(ip == undefined)	{
			send2log("Unable to find local IP");
			el.innerHTML = "<pre>Unknown</pre>";
		}
		else	{
			send2log("Detected local IP");
			var range = IP.ip2networkAddr(WebRTC.current_ip, 24);
			document.getElementById("ips2scan").value = range + "/24";
			el.innerHTML = "<pre>" + WebRTC.current_ip + "</pre>";
		}
	};
	WebRTC.internal_ip();
}


function btn_get_response(cid)	{
	Network.request("GET", "/client/httpresponse/" + cid, null, function(xhr)	{
		if(xhr.status == 200)	{
			var obj = Misc.parse_network2default(xhr, {"httpresponse":""});
			var str = atob(obj["httpresponse"]);

			// Quick way to get it encoded
			var str = str.replace(/</g,"&lt;").replace(/>/g,"&gt;");
			document.getElementById("httpresponseresult").innerHTML = str;
			send2log("Updated with HTTP response");
		}
		else	{
			document.getElementById("httpresponseresult").innerHTML = "";
			send2log("Unable to get httpresponse for client");
		}
	});
}

function btn_get_dbdump(cid)	{
	Network.request("GET", "/client/harvested/" + cid, null, function(xhr)	{
		if(xhr.status == 200)	{
			var obj = Misc.parse_network2default(xhr, {});
			var str = JSON.stringify(obj, null, 2);
			str.replace(/</g,"&lt;").replace(/>/g,"&gt;")
			document.getElementById("httpresponseresult").innerHTML = str;
			send2log("Updated with dump from database");
		}
		else	{
			document.getElementById("httpresponseresult").innerHTML = "";
			send2log("Unable to get database dump for client");
		}
	});
}

function btn_launch_exploit(cid)	{
	var eid = getSelected(cid + "_exploit");
	var pid = getSelected(cid + "_payload");
	if(eid == null || eid == undefined || pid == null || pid == undefined)	{
		alert("You must select all values");
		return;
	}
	var ready = getClientValue(cid, 3);
	if(ready != "Ready")	{
		alert("DNS rebinding is not complete or was not successful");
		return;
	}
	saveOptions();
	var options = optionsModule(eid, pid);
	Network.request_advanced("POST", "/client/exploit/" + cid + "/" + eid + "/" + pid,
		JSON.stringify(options), function(xhr, method, resource, data, user, pass)	{
			console.log(xhr);
			send2log("Sent exploit request to server");
		}
	);
}

function addAvailablePayloads(eid, sid)	{
	clearSelect(sid, "Select payload");
	if(eid == "" || eid == null || eid == undefined)	{
		return;
	}
	else	{
		for(var i = 0; i < EXPLOITS[eid].length; i++)	{
			addOptionSelect(sid, EXPLOITS[eid][i]);
		}
	}
}

// Notify server that we should delete all information about ourselves
function deleteMe()	{
	var selfid = document.domain.split(".")[0];
	console.log(selfid);
	Network.request("POST", "/client/delete/" + selfid, null, function(xhr)	{
		console.log("Delete");
		if(xhr.status == 200)	{
			send2log("Sent delete request and recieved " + xhr.responseText);
			clearJS();
			// Current page will no longer work, so we redirect to front page
//			var arr = document.domain.split(".");
//			arr.shift();	// Remove first subdomain
//			window.location = "http://" + arr.join(".") + "/";
		}
		else	{
			send2log("Unable to send delete request to server");
		}
	});
}


// -------------- Callback functions ------------------------ //

function cb_ip_up(ip)	{
	send2log("Detected IP: " + ip + " as up");
	addIPSelect(ip);
}

function cb_ip_scan_done(up, down)	{
	send2log("IP scan done, detected " + String(up) + " as up and " + String(down) + " as down");
}

function cb_get_service(xhr, method, resource, data, user, pass)	{
	var paths = resource.split("/");
	var cid = paths[paths.length-1];
	if(xhr.status == 200)	{
		var obj = Misc.parse_network2default(xhr, []);
		send2log("Found service running at: " + GLOBAL[cid]["ip"] + ":" + GLOBAL[cid]["port"]);
		updateClient(cid, null, null, "Ready");

		for(var i = 0; i < obj.length; i++)	{
			var added = "";
			if("info" in obj[i])	{
				added = " (" + obj[i]["info"] + ")";
			}
			send2log(GLOBAL[cid]["ip"] + ":" + GLOBAL[cid]["port"] + " matched against " +
				JSON.stringify(obj[i]));
			GLOBAL[cid]["product"] = obj[i];

		}
		// Get available modules
		Network.request_advanced("GET", "/client/modules/" + cid, null, cb_available_modules);
	}
	else	{
		GLOBAL[cid]["attempts"] += 1;
		console.log("Client has not found service yet: " + String(GLOBAL[cid]["attempts"]));
		if(GLOBAL[cid]["attempts"] > 20)	{
			send2log("Failed to perform rebinding on " + GLOBAL[cid]["ip"] + ":" + GLOBAL[cid]["port"]);
			updateClient(cid, null, null, "Failed");
		}
		else	{
			window.setTimeout(function()	{
				Network.request_advanced("GET", "/client/product/" + cid, null, cb_get_service);
			}, 10000);
		}
	}
}

function cb_available_modules(xhr, method, resource, data, user, pass)	{
	var paths = resource.split("/");
	var cid = paths[paths.length-1];
	if(xhr.status == 200)	{
		var obj = Misc.parse_network2default(xhr, []);
		GLOBAL[cid]["modules"] = obj;
		if(obj.length > 0)	{
			updateExploits(cid, obj);
			send2log("Updated available modules for client " + cid);
		}
		else	{
			send2log("No modules found for product");
		}
	}
	else	{
		send2log("Unable to get modules for " + cid);
	}
}




// -------------- Helper functions -------------------------- //


// -------------- Functions related to options ------------------- //

function updateOption(opt, modid, optval="")	{
	if(opt in OPTIONS)	{
		if(OPTIONS[opt]["modules"].indexOf(modid) <= -1)	{
			OPTIONS[opt]["modules"].push(modid);
		}
		OPTIONS[opt]["value"] = optval;
	}
	else	{
		ins = {"value": optval, "modules": [modid]};
		OPTIONS[opt] = ins;
	}
}

function populateOptions(options, modid)	{
	var added = false;
	for(var i = 0; i < options.length; i++)	{
		updateOption(options[i], modid, "");
	}
}

function getOptionsModule(modtype, modid)	{
	Network.request("GET", "/client/options_" + modtype + "/" + modid, null, function(xhr)	{
		if(xhr.status == 200)	{
			obj = Misc.parse_network2default(xhr, [])
			populateOptions(obj, modid);
		}
		else	{
			send2log("Unable to find options for " + modid);
		}
	});
}

function updateExploits(cid, ids)	{
	clearSelect(cid + "_exploit", "Select exploit");
	clearSelect(cid + "_payload", "Select payload");

	for(var i = 0; i < ids.length; i++)	{
		addOptionSelect(cid + "_exploit", ids[i]);
	}
}

function clearSelect(id, text)	{
	var sel = document.getElementById(id);
	sel.innerHTML = '<option value="">' + text + '</option>';

}

function addOptionSelect(selectid, v)	{
	var select = document.getElementById(selectid);
	var option = document.createElement("option");
	option.value = v;
	option.innerHTML = v;
	select.appendChild(option);

}

// Clear the client table so it has zero rows after header
function clearClientTable()	{
	var table = document.getElementById("client_table");
	table.setAttribute("class", "table table-responsive fixed-table-body")
	table.innerHTML = "<tr><th>ID</th><th>IP</th><th>Port</th><th>Status</th><th></th><th></th><th></th><th></th><th></th><th></th></tr>";
}

function getSelected(id)	{
	var sel = document.getElementById(id);
	var ret = sel.options[sel.selectedIndex].value;
	return ret;
}

function send2log(msg)	{
	var date = new Date();
//	var pre = document.createElement("pre");
	var txt = document.createTextNode(date + " | " + msg)
//	pre.appendChild(txt);
	var el = document.getElementById("logcontainer");
	el.innerHTML += date + " | " + msg + "\n";
//	el.appendChild(pre);
}

function clearJS()	{
	OPTIONS = {};
	GLOBAL = {};
}

// Add a list of default exploits to row with id=id
function addDefaultExploits(id)	{
	for(var key in EXPLOITS)	{
		addOptionSelect(id, key);
	}
}

function get_payloads()	{
	for(var key in EXPLOITS)	{
		Network.request_advanced("GET", "/client/payloads/" + key, null, function(xhr, method, resource, data, user, pass)	{
			var key2 = resource.split("/")[3];
			var items = Misc.parse_network2default(xhr, []);
			EXPLOITS[key2] = items;
			for(var i = 0; i < items.length; i++)	{
				getOptionsModule("payload", items[i]);
			}
		});
	}
}

function get_exploits()	{
	Network.request("GET", "/client/possible/modules", null, function(xhr)	{
		var items = Misc.parse_network2default(xhr, []);
		for(var i = 0; i < items.length; i++)	{
			EXPLOITS[items[i]] = [];
			getOptionsModule("exploit", items[i]);	// Get options for exploits
		}
		get_payloads();
	});
}


// ----------------- clienttable ------------------------ //

function clientListed(id)	{
	var table = document.getElementById("client_table");
	var trs = table.getElementsByTagName("tr");
	for(var i = 1; i < trs.length; i++)	{
		if(trs[i].id == id)	{
			return trs[i];
		}
	}
	return undefined;
}


function addClient(id, ip, port, connected)	{
	var table = document.getElementById("client_table");
	var tr = document.createElement("tr");
	tr.id = id;

	var td1 = document.createElement("td");
	td1.appendChild(document.createTextNode(id));

	var td2 = document.createElement("td");
	td2.appendChild(document.createTextNode(ip));

	var td3 = document.createElement("td");
	td3.appendChild(document.createTextNode(port));

	var td4 = document.createElement("td");
	td4.appendChild(document.createTextNode(connected));

	var td6 = document.createElement("td");	// exploits
	td6.setAttribute("class", "text-center");
	var eselect = document.createElement("select");
	eselect.id = id + "_exploit";
	eselect.setAttribute("class", "form-control");
	eselect.setAttribute("onchange", "addAvailablePayloads(getSelected('" + id + "_exploit'), '" + id + "_payload');moduleChanged('" + id + "', 'exploit');");

	var eoption = document.createElement("option");
	eoption.value = "";
	eoption.innerHTML = "Select exploit";
	eselect.appendChild(eoption);

	td6.appendChild(eselect);


	var td7 = document.createElement("td");	// payloads
	td7.setAttribute("class", "text-center");
	var pselect = document.createElement("select");
	pselect.id = id + "_payload";
	pselect.setAttribute("onchange", "moduleChanged('" + id + "', 'payload');");
	pselect.setAttribute("class", "form-control");

	var poption = document.createElement("option");
	poption.value = "";
	poption.innerHTML = "Select payload";
	pselect.appendChild(poption);

	td7.appendChild(pselect);


	var td8 = document.createElement("td");	// button
	td8.setAttribute("class", "text-center");
	var btn = document.createElement("input");
	btn.id = id + "_button";
	btn.type = "button";
	btn.setAttribute("class", "btn btn-danger");
	btn.setAttribute("onclick", "btn_launch_exploit('" + id + "');");
	btn.value = "Exploit";
	td8.appendChild(btn);

	var td9 = document.createElement("td");	// get response
	td9.setAttribute("class", "text-center");
	var btn2 = document.createElement("input");
	btn2.id = id + "_response";
	btn2.type = "button";
	btn2.setAttribute("class", "btn btn-info");
	btn2.setAttribute("onclick", "btn_get_response('" + id + "');");
	btn2.value = "HTTP response";
	td9.appendChild(btn2);

	var td10 = document.createElement("td");	// get DB dump
	td10.setAttribute("class", "text-center");
	var btn3 = document.createElement("input");
	btn3.id = id + "_dbdump";
	btn3.type = "button";
	btn3.setAttribute("class", "btn btn-info");
	btn3.setAttribute("onclick", "btn_get_dbdump('" + id + "');");
	btn3.value = "DB dump";
	td10.appendChild(btn3);

	var td11 = document.createElement("td");
	td11.setAttribute("class", "text-center");
	var btn4 = document.createElement("input");
	btn4.id = id + "_getmodules";
	btn4.type = "button";
	btn4.setAttribute("class", "btn btn-info");
	btn4.setAttribute("onclick", "Network.request_advanced('GET', '/client/modules/" + id + "', null, cb_available_modules);");
	btn4.value = "Get modules again";
	td11.appendChild(btn4);

	tr.appendChild(td1);
	tr.appendChild(td2);
	tr.appendChild(td3);
	tr.appendChild(td4);
	tr.appendChild(td6);
	tr.appendChild(td7);
	tr.appendChild(td8);
	tr.appendChild(td9);
	tr.appendChild(td10);
	tr.appendChild(td11);

	table.appendChild(tr);
	addDefaultExploits(id + "_exploit");
}

function getClientValue(cid, row)	{
	var table = document.getElementById("client_table");
	var trs = table.getElementsByTagName("tr");
	for(var i = 1; i < trs.length; i++)	{
		if(trs[i].id == cid)	{
		  tds = trs[i].getElementsByTagName("td");
		  return tds[row].innerHTML;
		}
	}
	return null;
}

function updateClient(id, ip, port, connected)	{
	var table = document.getElementById("client_table");
	var tr = clientListed(id);
	if(tr == undefined)	{
		addClient(id, ip, port, connected);
	}
	else	{
		var tds = tr.getElementsByTagName("td");
		if(ip != null && ip != undefined)	{
			tds[1].innerHTML = ip;
		}
		if(port != null && port != undefined)	{
			tds[2].innerHTML = port;
		}
		if(connected != null && connected != undefined)	{
			tds[3].innerHTML = connected;
		}
	}
}

// ----------------- optionstable ------------------------ //

function saveOptions()	{
	var ret = {}
	var table = document.getElementById("optionstable");
	var inputs = table.getElementsByTagName("input");
	for(var i = 0; i < inputs.length; i++)	{
		var optval = inputs[i].value;
		if(inputs[i].id.indexOf("LIST") == 0)	{
			optval = optval.split(",");
		}
		OPTIONS[inputs[i].id]["value"] = optval;
		ret[inputs[i].id] = optval;
	}
	return ret;
}

function clearOptions()	{
	saveOptions();	// save current options

	var table = document.getElementById("optionstable");
	table.setAttribute("class", "table");
	table.innerHTML = "<tr><th>Name</th><th>Value</th></tr>";
}

function optionListed(key)	{
	var table = document.getElementById("optionstable");
	var inputs = table.getElementsByTagName("input");
	for(var i = 0; i < inputs.length; i++)	{
		if(inputs[i].id == key)	return true;
	}
	return false;
}

function addOptionValue(key, val)	{
	var table = document.getElementById("optionstable");

	var tr = document.createElement("tr");
	var td1 = document.createElement("td");
	td1.appendChild(document.createTextNode(key));

	var td2 = document.createElement("td");
	var input = document.createElement("input");
	input.type = "text";
	input.id = key;
	input.value = val
	input.placeholder = "Config value";
	td2.appendChild(input);

	// Append to row
	tr.appendChild(td1);
	tr.appendChild(td2);

	// Append to table
	table.appendChild(tr);
}

function addOptionsModule(modid)	{
	for(var key in OPTIONS)	{
		if(OPTIONS[key]["modules"].indexOf(modid) >= 0)	{
			addOption(key);
		}
	}
}

function optionsModule(eid, pid)	{
	var ret = {};
	for(var key in OPTIONS)	{
		if(OPTIONS[key]["modules"].indexOf(eid) || OPTIONS[key]["modules"].indexOf(pid))	{
			ret[key] = OPTIONS[key]["value"];
		}
	}
	console.log(ret);
	return ret;
}

function moduleChanged(id, modtype)	{
	clearOptions();
	addOptionsModule(getSelected(id + "_exploit"));
	if(modtype == "payload")	{
		addOptionsModule(getSelected(id + "_payload"));
	}
}

function addOption(key)	{
	if(optionListed(key))	return;
	var val = OPTIONS[key]["value"];
	addOptionValue(key, val);
}

// ----------------- DNS rebinding ------------------------ //

function dns_done(home, id, ip, port, status)	{
	if(status == "success")	{
		GLOBAL[id] = {}
		GLOBAL[id]["ip"] = ip;
		GLOBAL[id]["port"] = port;
		send2log("Successfully loaded code targeting: " + ip + ":" + String(port));
		updateClient(id, ip, port, "Loaded");
		get_service(id, ip, port);
	}
	else	{
		send2log("Failed to perform rebinding on: " + ip + ":" + String(port));
	}
}

function perform_dns_rebind(ip, port)	{
	send2log("Performing DNS rebinding on " + ip + ":" + port + " (takes about a minute)");
	var rebind = Misc.copy_module(Rebind);
	rebind.localip = ip;
	rebind.localport = port;
	rebind.cb_done_initial = dns_done;
	rebind.perform();
}


function get_service(cid, ip, port)	{
	send2log("Trying to detect service at " + ip + ":" + String(port));
	GLOBAL[cid]["attempts"] = 0;
	window.setTimeout(
		function()	{
			Network.request_advanced("GET", "/client/product/" + cid, null, cb_get_service);
		},
		2000
	);
}
