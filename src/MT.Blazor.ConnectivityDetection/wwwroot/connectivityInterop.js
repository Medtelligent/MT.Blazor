/******/ // The require scope
/******/ var __webpack_require__ = {};
/******/ 
/************************************************************************/
/******/ /* webpack/runtime/define property getters */
/******/ (() => {
/******/ 	// define getter functions for harmony exports
/******/ 	__webpack_require__.d = (exports, definition) => {
/******/ 		for(var key in definition) {
/******/ 			if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 				Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 			}
/******/ 		}
/******/ 	};
/******/ })();
/******/ 
/******/ /* webpack/runtime/hasOwnProperty shorthand */
/******/ (() => {
/******/ 	__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ })();
/******/ 
/******/ /* webpack/runtime/make namespace object */
/******/ (() => {
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = (exports) => {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/ })();
/******/ 
/************************************************************************/
var __webpack_exports__ = {};
/*!**************************!*\
  !*** ./Scripts/index.js ***!
  \**************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "status": () => (/* binding */ status),
/* harmony export */   "start": () => (/* binding */ start),
/* harmony export */   "stop": () => (/* binding */ stop)
/* harmony export */ });
let worker = null;
let running = false;
let lastStatus, lastData;
function status() {
  return {
    status: lastStatus,
    checkType: lastData ? lastData.checkType : null,
    latency: lastData ? lastData.latency : 0
  };
}
function start(options) {
  if (running) {
    return;
  }

  const callback = options.callback;
  worker = new Worker(options.worker);
  worker.addEventListener('message', function (e) {
    lastData = e.data;
    const newStatus = typeof e.data === "object" ? e.data.online ? e.data.latency >= 500 ? 'Slow' : 'Online' : 'Offline' : null;

    if (newStatus === lastStatus) {
      return;
    }

    console.debug(`[connectivity] connection status changed from '${lastStatus || 'Unknown'}' to '${newStatus}'`);
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
  });
  window.addEventListener('online', function () {
    console.debug(`[connectivity:window] online`);
  });
  window.addEventListener('offline', function () {
    console.debug(`[connectivity:window] offline`);
  });
  running = true;
}
function stop() {
  worker.postMessage({
    cmd: 'stop'
  });
  running = false;
}
var __webpack_exports__start = __webpack_exports__.start;
var __webpack_exports__status = __webpack_exports__.status;
var __webpack_exports__stop = __webpack_exports__.stop;
export { __webpack_exports__start as start, __webpack_exports__status as status, __webpack_exports__stop as stop };

//# sourceMappingURL=data:application/json;charset=utf-8;base64,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cmNlcyI6WyJ3ZWJwYWNrOi8vbXQuYmxhem9yLmNvbm5lY3Rpdml0eS93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9tdC5ibGF6b3IuY29ubmVjdGl2aXR5L3dlYnBhY2svcnVudGltZS9kZWZpbmUgcHJvcGVydHkgZ2V0dGVycyIsIndlYnBhY2s6Ly9tdC5ibGF6b3IuY29ubmVjdGl2aXR5L3dlYnBhY2svcnVudGltZS9oYXNPd25Qcm9wZXJ0eSBzaG9ydGhhbmQiLCJ3ZWJwYWNrOi8vbXQuYmxhem9yLmNvbm5lY3Rpdml0eS93ZWJwYWNrL3J1bnRpbWUvbWFrZSBuYW1lc3BhY2Ugb2JqZWN0Iiwid2VicGFjazovL210LmJsYXpvci5jb25uZWN0aXZpdHkvLi9TY3JpcHRzL2luZGV4LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIi8vIFRoZSByZXF1aXJlIHNjb3BlXG52YXIgX193ZWJwYWNrX3JlcXVpcmVfXyA9IHt9O1xuXG4iLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwibGV0IHdvcmtlciA9IG51bGw7XHJcbmxldCBydW5uaW5nID0gZmFsc2U7XHJcbmxldCBsYXN0U3RhdHVzLCBsYXN0RGF0YTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBzdGF0dXMoKSB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICAgIHN0YXR1czogbGFzdFN0YXR1cyxcclxuICAgICAgICBjaGVja1R5cGU6IGxhc3REYXRhID8gbGFzdERhdGEuY2hlY2tUeXBlIDogbnVsbCxcclxuICAgICAgICBsYXRlbmN5OiBsYXN0RGF0YSA/IGxhc3REYXRhLmxhdGVuY3kgOiAwXHJcbiAgICB9O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gc3RhcnQob3B0aW9ucykge1xyXG4gICAgaWYgKHJ1bm5pbmcpIHtcclxuICAgICAgICByZXR1cm47XHJcbiAgICB9XHJcbiAgICBcclxuICAgIGNvbnN0IGNhbGxiYWNrID0gb3B0aW9ucy5jYWxsYmFjaztcclxuICAgIFxyXG4gICAgd29ya2VyID0gbmV3IFdvcmtlcihvcHRpb25zLndvcmtlcik7XHJcbiAgICB3b3JrZXIuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIGZ1bmN0aW9uIChlKSB7XHJcbiAgICAgICAgbGFzdERhdGEgPSBlLmRhdGE7XHJcbiAgICAgICAgXHJcbiAgICAgICAgY29uc3QgbmV3U3RhdHVzID0gdHlwZW9mKGUuZGF0YSkgPT09IFwib2JqZWN0XCJcclxuICAgICAgICAgICAgPyBlLmRhdGEub25saW5lXHJcbiAgICAgICAgICAgICAgICA/IGUuZGF0YS5sYXRlbmN5ID49IDUwMFxyXG4gICAgICAgICAgICAgICAgICAgID8gJ1Nsb3cnXHJcbiAgICAgICAgICAgICAgICAgICAgOiAnT25saW5lJ1xyXG4gICAgICAgICAgICAgICAgOiAnT2ZmbGluZSdcclxuICAgICAgICAgICAgOiBudWxsO1xyXG5cclxuICAgICAgICBpZiAobmV3U3RhdHVzID09PSBsYXN0U3RhdHVzKSB7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcbiAgICAgICAgXHJcbiAgICAgICAgY29uc29sZS5kZWJ1ZyhgW2Nvbm5lY3Rpdml0eV0gY29ubmVjdGlvbiBzdGF0dXMgY2hhbmdlZCBmcm9tICckeyhsYXN0U3RhdHVzIHx8ICdVbmtub3duJyl9JyB0byAnJHtuZXdTdGF0dXN9J2ApO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGxhc3RTdGF0dXMgPSBuZXdTdGF0dXM7XHJcbiAgICAgICAgXHJcbiAgICAgICAgaWYgKGNhbGxiYWNrKSB7XHJcbiAgICAgICAgICAgIGNhbGxiYWNrLmluc3RhbmNlLmludm9rZU1ldGhvZEFzeW5jKGNhbGxiYWNrLm1ldGhvZE5hbWUsIHtcclxuICAgICAgICAgICAgICAgIHN0YXR1czogbGFzdFN0YXR1cyxcclxuICAgICAgICAgICAgICAgIGNoZWNrVHlwZTogbGFzdERhdGEuY2hlY2tUeXBlLFxyXG4gICAgICAgICAgICAgICAgbGF0ZW5jeTogbGFzdERhdGEubGF0ZW5jeVxyXG4gICAgICAgICAgICB9KTtcclxuICAgICAgICB9XHJcbiAgICB9LCBmYWxzZSk7XHJcbiAgICBcclxuICAgIHdvcmtlci5wb3N0TWVzc2FnZSh7XHJcbiAgICAgICAgY21kOiAnc3RhcnQnLFxyXG4gICAgICAgIHBpbmc6IG9wdGlvbnMucGluZ1xyXG4gICAgfSlcclxuICAgIFxyXG4gICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ29ubGluZScsIGZ1bmN0aW9uICgpIHtcclxuICAgICAgICBjb25zb2xlLmRlYnVnKGBbY29ubmVjdGl2aXR5OndpbmRvd10gb25saW5lYCk7XHJcbiAgICB9KTtcclxuICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdvZmZsaW5lJywgZnVuY3Rpb24gKCkge1xyXG4gICAgICAgIGNvbnNvbGUuZGVidWcoYFtjb25uZWN0aXZpdHk6d2luZG93XSBvZmZsaW5lYCk7XHJcbiAgICB9KTtcclxuICAgIFxyXG4gICAgcnVubmluZyA9IHRydWU7XHJcbn1cclxuICAgIFxyXG5leHBvcnQgZnVuY3Rpb24gc3RvcCgpIHtcclxuICAgIHdvcmtlci5wb3N0TWVzc2FnZSh7XHJcbiAgICAgICAgY21kOiAnc3RvcCdcclxuICAgIH0pO1xyXG4gICAgXHJcbiAgICBydW5uaW5nID0gZmFsc2U7XHJcbn0iXSwibmFtZXMiOlsid29ya2VyIiwicnVubmluZyIsImxhc3RTdGF0dXMiLCJsYXN0RGF0YSIsInN0YXR1cyIsImNoZWNrVHlwZSIsImxhdGVuY3kiLCJzdGFydCIsIm9wdGlvbnMiLCJjYWxsYmFjayIsIldvcmtlciIsImFkZEV2ZW50TGlzdGVuZXIiLCJlIiwiZGF0YSIsIm5ld1N0YXR1cyIsIm9ubGluZSIsImNvbnNvbGUiLCJkZWJ1ZyIsImluc3RhbmNlIiwiaW52b2tlTWV0aG9kQXN5bmMiLCJtZXRob2ROYW1lIiwicG9zdE1lc3NhZ2UiLCJjbWQiLCJwaW5nIiwid2luZG93Iiwic3RvcCJdLCJzb3VyY2VSb290IjoiIn0=