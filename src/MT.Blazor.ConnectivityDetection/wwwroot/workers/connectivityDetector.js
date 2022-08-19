let timerId;
let checking = false;
let ping = null;
const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;

function doPingTest(url) {
    if (checking) {
        return;
    }
    
    let tEnd;
    let tStart = performance.now();
    
    checking = true;

    fetch(url)
        .then(res => {
            checking = false;
            
            tEnd = performance.now();
            
            self.postMessage({
                online: res.ok,
                checkType: 'ping',
                latency: tEnd-tStart
            });
        })
        .catch(err => {
            checking = false;
            
            tEnd = performance.now();
            
            self.postMessage({
                online: false,
                checkType: 'ping',
                latency: tEnd-tStart
            });
            
            console.error(`[connectivity:ping] error pinging ${url}; latency: ${tEnd-tStart}`, err);
        });
}

function doConnectionTest(e, pingUrl) {
    const netInfo = (e && e.target) || connection;
    
    console.debug(`[connectivity:connection] onLine: ${navigator.onLine}; effectiveType: ${netInfo.effectiveType}; rtt: ${netInfo.rtt}; downlink: ${netInfo.downlink}`);

    const latency = netInfo.effectiveType === '4g'
        ? netInfo.downlink === 10
            ? 50
            : netInfo.downlink >= 5
                ? 500
                : 1000
        : netInfo.effectiveType === '3g'
        ? 500
        : 1000;

    if (pingUrl && latency > 50) {
        console.debug(`[connectivity:connection] verifying slow NetworkInformation API latency (${latency}) with ping check to ${pingUrl}`);
        doPingTest(pingUrl);
        return;
    }

    self.postMessage({
        online: navigator.onLine,
        checkType: 'connection',
        latency: latency
    });
}

self.addEventListener('message',  e => {
    if (e.data.cmd === 'start') {
        ping = e.data.ping;
        
        if (connection) {
            connection.addEventListener('change', function(e) {
                doConnectionTest(e, ping.url);
            });
            
            doConnectionTest(null, ping.url);
        }
        
        if (ping) {
            doPingTest(ping.url);

            timerId = setInterval( () => {
                doPingTest(ping.url);
            }, ping.interval);
        }
        
        if (!ping && !connection) {
            self.postMessage('');
        }
    } else if(e.data.cmd === 'stop') {
        if (connection) {
            connection.removeEventListener('change', doConnectionTest);
        }
        
        if (timerId) {
            clearInterval(timerId);
        }
    }
});