let worker = null;
let running = false;
let lastStatus, lastData;

export function status() {
    return {
        status: lastStatus,
        checkType: lastData ? lastData.checkType : null,
        latency: lastData ? lastData.latency : 0
    };
}

export function start(options) {
    if (running) {
        return;
    }
    
    const callback = options.callback;
    
    worker = new Worker(options.worker);
    worker.addEventListener('message', function (e) {
        lastData = e.data;
        
        const newStatus = typeof(e.data) === "object"
            ? e.data.online
                ? e.data.latency >= 500
                    ? 'Slow'
                    : 'Online'
                : 'Offline'
            : null;

        if (newStatus === lastStatus) {
            return;
        }
        
        console.debug(`[connectivity] connection status changed from '${(lastStatus || 'Unknown')}' to '${newStatus}'`);
        
        lastStatus = newStatus;
        
        if (callback) {
            callback.instance.invokeMethodAsync(callback.methodName, {
                status: lastStatus,
                checkType: lastData.checkType,
                latency: lastData.latency
            });
        }
    }, false);
    
    worker.postMessage({
        cmd: 'start',
        ping: options.ping
    })
    
    window.addEventListener('online', function () {
        console.debug(`[connectivity:window] online`);
    });
    window.addEventListener('offline', function () {
        console.debug(`[connectivity:window] offline`);
    });
    
    running = true;
}
    
export function stop() {
    worker.postMessage({
        cmd: 'stop'
    });
    
    running = false;
}