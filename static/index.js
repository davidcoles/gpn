const origin = window.location.origin

function status() {

    const statusUrl = origin + '/api/1/status'
    const beaconUrl = origin + '/api/1/beacon'


    var start = false
    var beacon = false
    var status = null
    
    function getStatus() {
	
	getJSON(statusUrl, function(err, data) {
	    if (err !== null) {
		console.log('Something went wrong: ' + err)
		status = null
            } else {
		if(data !== null) {
		    status = data
		    
		    getJSON(beaconUrl, function(err, data) {
			if (err !== null) {
			    beacon = false
			} else {
			    if(data !== null) {
				beacon = data.beacon
			    } else {
				beacon = false
			    }
			}
		    })
		    
		} else {
		    status = null
		}
	    }
	    
	    start = true	    
	})
	
	setTimeout(getStatus, 5000)
    }

    function refresh() {
	
	var nd = document.createElement("div")
        nd.id = "status"
	
        if(!start) {
	    nd.innerHTML = "Status: Initialising ..."
            document.body.style.backgroundColor = "#aaa";
	} else if(status === null) {
	    nd.innerHTML = "Status: Unreachable"
            document.body.style.backgroundColor = "#faa";
	} else {
	    if(status.authenticated) {
		if(beacon) {
		    nd.innerHTML = "Status: Logged in as "+status.user
                    document.body.style.backgroundColor = "#cfc"
		} else {
		    nd.innerHTML = "Status: Logged in as "+status.user+", but private nework is not reachable. Try enabling WireGuard?"
                    document.body.style.backgroundColor = "#ffa"
		}
	    } else {
		nd.innerHTML = "Status: Please login to enable VPN"
                document.body.style.backgroundColor = "#ccf"
	    }
	}

	document.querySelectorAll('#status')[0].replaceWith(nd)
	
	setTimeout(refresh, 1000)
    }
    
    getStatus()
    refresh()
}


var getJSON = function(url, callback) {
    var xhr = new XMLHttpRequest();
    xhr.timeout = 1000
    xhr.open('GET', url, true);
    xhr.responseType = 'json';
    //xhr.onload = function() {
    xhr.onreadystatechange = function() {
        var status = xhr.status;
	console.log("status ", status);
        if (status === 200) {
            callback(null, xhr.response);
        } else {
            callback(status, xhr.response);
        }
    };
    xhr.send();
};

var get = function(url) {
    var xhr = new XMLHttpRequest();
    xhr.timeout = 1000
    xhr.open('GET', url, true);
    xhr.responseType = 'json';
    //xhr.onload = function() {
    xhr.onreadystatechange = function() {
        var status = xhr.status;
	console.log("GET", status);
    };
    xhr.send();
};
