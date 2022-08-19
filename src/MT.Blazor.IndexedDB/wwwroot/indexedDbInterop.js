/******/ var __webpack_modules__ = ({

/***/ "./node_modules/idb/build/esm/index.js":
/*!*********************************************!*\
  !*** ./node_modules/idb/build/esm/index.js ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "unwrap": () => (/* reexport safe */ _wrap_idb_value_js__WEBPACK_IMPORTED_MODULE_0__.u),
/* harmony export */   "wrap": () => (/* reexport safe */ _wrap_idb_value_js__WEBPACK_IMPORTED_MODULE_0__.w),
/* harmony export */   "deleteDB": () => (/* binding */ deleteDB),
/* harmony export */   "openDB": () => (/* binding */ openDB)
/* harmony export */ });
/* harmony import */ var _wrap_idb_value_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./wrap-idb-value.js */ "./node_modules/idb/build/esm/wrap-idb-value.js");



/**
 * Open a database.
 *
 * @param name Name of the database.
 * @param version Schema version.
 * @param callbacks Additional callbacks.
 */
function openDB(name, version, { blocked, upgrade, blocking, terminated } = {}) {
    const request = indexedDB.open(name, version);
    const openPromise = (0,_wrap_idb_value_js__WEBPACK_IMPORTED_MODULE_0__.w)(request);
    if (upgrade) {
        request.addEventListener('upgradeneeded', (event) => {
            upgrade((0,_wrap_idb_value_js__WEBPACK_IMPORTED_MODULE_0__.w)(request.result), event.oldVersion, event.newVersion, (0,_wrap_idb_value_js__WEBPACK_IMPORTED_MODULE_0__.w)(request.transaction));
        });
    }
    if (blocked)
        request.addEventListener('blocked', () => blocked());
    openPromise
        .then((db) => {
        if (terminated)
            db.addEventListener('close', () => terminated());
        if (blocking)
            db.addEventListener('versionchange', () => blocking());
    })
        .catch(() => { });
    return openPromise;
}
/**
 * Delete a database.
 *
 * @param name Name of the database.
 */
function deleteDB(name, { blocked } = {}) {
    const request = indexedDB.deleteDatabase(name);
    if (blocked)
        request.addEventListener('blocked', () => blocked());
    return (0,_wrap_idb_value_js__WEBPACK_IMPORTED_MODULE_0__.w)(request).then(() => undefined);
}

const readMethods = ['get', 'getKey', 'getAll', 'getAllKeys', 'count'];
const writeMethods = ['put', 'add', 'delete', 'clear'];
const cachedMethods = new Map();
function getMethod(target, prop) {
    if (!(target instanceof IDBDatabase &&
        !(prop in target) &&
        typeof prop === 'string')) {
        return;
    }
    if (cachedMethods.get(prop))
        return cachedMethods.get(prop);
    const targetFuncName = prop.replace(/FromIndex$/, '');
    const useIndex = prop !== targetFuncName;
    const isWrite = writeMethods.includes(targetFuncName);
    if (
    // Bail if the target doesn't exist on the target. Eg, getAll isn't in Edge.
    !(targetFuncName in (useIndex ? IDBIndex : IDBObjectStore).prototype) ||
        !(isWrite || readMethods.includes(targetFuncName))) {
        return;
    }
    const method = async function (storeName, ...args) {
        // isWrite ? 'readwrite' : undefined gzipps better, but fails in Edge :(
        const tx = this.transaction(storeName, isWrite ? 'readwrite' : 'readonly');
        let target = tx.store;
        if (useIndex)
            target = target.index(args.shift());
        // Must reject if op rejects.
        // If it's a write operation, must reject if tx.done rejects.
        // Must reject with op rejection first.
        // Must resolve with op value.
        // Must handle both promises (no unhandled rejections)
        return (await Promise.all([
            target[targetFuncName](...args),
            isWrite && tx.done,
        ]))[0];
    };
    cachedMethods.set(prop, method);
    return method;
}
(0,_wrap_idb_value_js__WEBPACK_IMPORTED_MODULE_0__.r)((oldTraps) => ({
    ...oldTraps,
    get: (target, prop, receiver) => getMethod(target, prop) || oldTraps.get(target, prop, receiver),
    has: (target, prop) => !!getMethod(target, prop) || oldTraps.has(target, prop),
}));




/***/ }),

/***/ "./node_modules/idb/build/esm/wrap-idb-value.js":
/*!******************************************************!*\
  !*** ./node_modules/idb/build/esm/wrap-idb-value.js ***!
  \******************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "a": () => (/* binding */ reverseTransformCache),
/* harmony export */   "i": () => (/* binding */ instanceOfAny),
/* harmony export */   "r": () => (/* binding */ replaceTraps),
/* harmony export */   "u": () => (/* binding */ unwrap),
/* harmony export */   "w": () => (/* binding */ wrap)
/* harmony export */ });
const instanceOfAny = (object, constructors) => constructors.some((c) => object instanceof c);

let idbProxyableTypes;
let cursorAdvanceMethods;
// This is a function to prevent it throwing up in node environments.
function getIdbProxyableTypes() {
    return (idbProxyableTypes ||
        (idbProxyableTypes = [
            IDBDatabase,
            IDBObjectStore,
            IDBIndex,
            IDBCursor,
            IDBTransaction,
        ]));
}
// This is a function to prevent it throwing up in node environments.
function getCursorAdvanceMethods() {
    return (cursorAdvanceMethods ||
        (cursorAdvanceMethods = [
            IDBCursor.prototype.advance,
            IDBCursor.prototype.continue,
            IDBCursor.prototype.continuePrimaryKey,
        ]));
}
const cursorRequestMap = new WeakMap();
const transactionDoneMap = new WeakMap();
const transactionStoreNamesMap = new WeakMap();
const transformCache = new WeakMap();
const reverseTransformCache = new WeakMap();
function promisifyRequest(request) {
    const promise = new Promise((resolve, reject) => {
        const unlisten = () => {
            request.removeEventListener('success', success);
            request.removeEventListener('error', error);
        };
        const success = () => {
            resolve(wrap(request.result));
            unlisten();
        };
        const error = () => {
            reject(request.error);
            unlisten();
        };
        request.addEventListener('success', success);
        request.addEventListener('error', error);
    });
    promise
        .then((value) => {
        // Since cursoring reuses the IDBRequest (*sigh*), we cache it for later retrieval
        // (see wrapFunction).
        if (value instanceof IDBCursor) {
            cursorRequestMap.set(value, request);
        }
        // Catching to avoid "Uncaught Promise exceptions"
    })
        .catch(() => { });
    // This mapping exists in reverseTransformCache but doesn't doesn't exist in transformCache. This
    // is because we create many promises from a single IDBRequest.
    reverseTransformCache.set(promise, request);
    return promise;
}
function cacheDonePromiseForTransaction(tx) {
    // Early bail if we've already created a done promise for this transaction.
    if (transactionDoneMap.has(tx))
        return;
    const done = new Promise((resolve, reject) => {
        const unlisten = () => {
            tx.removeEventListener('complete', complete);
            tx.removeEventListener('error', error);
            tx.removeEventListener('abort', error);
        };
        const complete = () => {
            resolve();
            unlisten();
        };
        const error = () => {
            reject(tx.error || new DOMException('AbortError', 'AbortError'));
            unlisten();
        };
        tx.addEventListener('complete', complete);
        tx.addEventListener('error', error);
        tx.addEventListener('abort', error);
    });
    // Cache it for later retrieval.
    transactionDoneMap.set(tx, done);
}
let idbProxyTraps = {
    get(target, prop, receiver) {
        if (target instanceof IDBTransaction) {
            // Special handling for transaction.done.
            if (prop === 'done')
                return transactionDoneMap.get(target);
            // Polyfill for objectStoreNames because of Edge.
            if (prop === 'objectStoreNames') {
                return target.objectStoreNames || transactionStoreNamesMap.get(target);
            }
            // Make tx.store return the only store in the transaction, or undefined if there are many.
            if (prop === 'store') {
                return receiver.objectStoreNames[1]
                    ? undefined
                    : receiver.objectStore(receiver.objectStoreNames[0]);
            }
        }
        // Else transform whatever we get back.
        return wrap(target[prop]);
    },
    set(target, prop, value) {
        target[prop] = value;
        return true;
    },
    has(target, prop) {
        if (target instanceof IDBTransaction &&
            (prop === 'done' || prop === 'store')) {
            return true;
        }
        return prop in target;
    },
};
function replaceTraps(callback) {
    idbProxyTraps = callback(idbProxyTraps);
}
function wrapFunction(func) {
    // Due to expected object equality (which is enforced by the caching in `wrap`), we
    // only create one new func per func.
    // Edge doesn't support objectStoreNames (booo), so we polyfill it here.
    if (func === IDBDatabase.prototype.transaction &&
        !('objectStoreNames' in IDBTransaction.prototype)) {
        return function (storeNames, ...args) {
            const tx = func.call(unwrap(this), storeNames, ...args);
            transactionStoreNamesMap.set(tx, storeNames.sort ? storeNames.sort() : [storeNames]);
            return wrap(tx);
        };
    }
    // Cursor methods are special, as the behaviour is a little more different to standard IDB. In
    // IDB, you advance the cursor and wait for a new 'success' on the IDBRequest that gave you the
    // cursor. It's kinda like a promise that can resolve with many values. That doesn't make sense
    // with real promises, so each advance methods returns a new promise for the cursor object, or
    // undefined if the end of the cursor has been reached.
    if (getCursorAdvanceMethods().includes(func)) {
        return function (...args) {
            // Calling the original function with the proxy as 'this' causes ILLEGAL INVOCATION, so we use
            // the original object.
            func.apply(unwrap(this), args);
            return wrap(cursorRequestMap.get(this));
        };
    }
    return function (...args) {
        // Calling the original function with the proxy as 'this' causes ILLEGAL INVOCATION, so we use
        // the original object.
        return wrap(func.apply(unwrap(this), args));
    };
}
function transformCachableValue(value) {
    if (typeof value === 'function')
        return wrapFunction(value);
    // This doesn't return, it just creates a 'done' promise for the transaction,
    // which is later returned for transaction.done (see idbObjectHandler).
    if (value instanceof IDBTransaction)
        cacheDonePromiseForTransaction(value);
    if (instanceOfAny(value, getIdbProxyableTypes()))
        return new Proxy(value, idbProxyTraps);
    // Return the same value back if we're not going to transform it.
    return value;
}
function wrap(value) {
    // We sometimes generate multiple promises from a single IDBRequest (eg when cursoring), because
    // IDB is weird and a single IDBRequest can yield many responses, so these can't be cached.
    if (value instanceof IDBRequest)
        return promisifyRequest(value);
    // If we've already transformed this value before, reuse the transformed value.
    // This is faster, but it also provides object equality.
    if (transformCache.has(value))
        return transformCache.get(value);
    const newValue = transformCachableValue(value);
    // Not all types are transformed.
    // These may be primitive types, so they can't be WeakMap keys.
    if (newValue !== value) {
        transformCache.set(value, newValue);
        reverseTransformCache.set(newValue, value);
    }
    return newValue;
}
const unwrap = (value) => reverseTransformCache.get(value);




/***/ }),

/***/ "./Scripts/interopClasses.ts":
/*!***********************************!*\
  !*** ./Scripts/interopClasses.ts ***!
  \***********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IndexedDB = exports.IndexedDBManager = void 0;
const idb_1 = __webpack_require__(/*! idb */ "./node_modules/idb/build/esm/index.js");
let getSchemaEntityNames = (list) => {
    let names = [];
    for (let i = 0; i < list.length; i++) {
        names.push(list[i].name);
    }
    return names;
};
class IndexedDBManager {
    constructor() {
        this._dbInstances = new Map();
        this.openDb = (dbSchema) => __awaiter(this, void 0, void 0, function* () {
            let db;
            try {
                db = this._dbInstances.get(dbSchema.name);
                if (!db || db.version < dbSchema.version) {
                    if (db) {
                        db.dispose();
                    }
                    db = new IndexedDB(dbSchema, yield (0, idb_1.openDB)(dbSchema.name, dbSchema.version, {
                        upgrade(db, oldVersion, newVersion, transaction) {
                            console.debug(`[idb].[${dbSchema.name}]: Deploying schema changes from ${oldVersion} to ${newVersion}`, dbSchema);
                            IndexedDBManager.upgradeDatabase(db, oldVersion, dbSchema, transaction);
                        },
                        blocked() {
                            console.debug(`[idb].[${dbSchema.name}]: Connection to database for version upgrade is blocked due to older versions open on the origin`, dbSchema);
                        },
                        blocking() {
                            console.debug(`[idb].[${dbSchema.name}]: This connection is blocking a version upgrade...recycling this connection`, dbSchema);
                        },
                        terminated() {
                            console.debug(`[idb].[${dbSchema.name}]: This connection was abnormally terminated by the browser...recycling this connection`, dbSchema);
                        }
                    }));
                    this._dbInstances.set(dbSchema.name, db);
                }
            }
            catch (e) {
                db = new IndexedDB(dbSchema, yield (0, idb_1.openDB)(dbSchema.name));
                this._dbInstances.set(dbSchema.name, db);
            }
            return db;
        });
        this.closeDb = (dbName) => __awaiter(this, void 0, void 0, function* () {
            const db = this._dbInstances.get(dbName);
            if (!db) {
                return;
            }
            db.dispose();
            this._dbInstances.delete(dbName);
        });
        this.deleteDb = (dbName) => __awaiter(this, void 0, void 0, function* () {
            const db = this._dbInstances.get(dbName);
            if (!db) {
                return;
            }
            db.dispose();
            yield (0, idb_1.deleteDB)(dbName);
            this._dbInstances.delete(dbName);
        });
        this.dbInfo = (dbName) => __awaiter(this, void 0, void 0, function* () {
            const db = yield (0, idb_1.openDB)(dbName);
            let getStores = (list) => {
                let stores = [];
                for (let i = 0; i < list.length; i++) {
                    let store = db.transaction(list[i]).store;
                    let indexes = [];
                    const indexNames = store.indexNames;
                    for (let s = 0; s < indexNames.length; s++) {
                        indexes.push({
                            name: indexNames[s]
                        });
                    }
                    stores.push({
                        name: list[i],
                        isKeyVal: !store.keyPath,
                        primaryKey: store.keyPath
                            ? { keyPath: store.keyPath }
                            : null,
                        indexes: indexes
                    });
                }
                return stores;
            };
            const info = {
                version: db.version,
                stores: getStores(db.objectStoreNames)
            };
            db.close();
            if (info.stores.length === 0) {
                yield (0, idb_1.deleteDB)(dbName);
            }
            console.debug(`[idb].[${dbName}]: Generated current schema summary`, info);
            return info;
        });
    }
    dispose() {
        this._dbInstances.forEach((db, name) => {
            db.dispose();
        });
    }
    static upgradeDatabase(upgradeDB, oldVersion, dbSchema, transaction) {
        if (oldVersion >= dbSchema.version || !dbSchema.stores) {
            return;
        }
        const schemaStoreNames = getSchemaEntityNames(dbSchema.stores);
        for (let store of upgradeDB.objectStoreNames) {
            if (!schemaStoreNames.includes(store)) {
                console.debug(`[idb].[${upgradeDB.name}]: Dropping store [${store}]`);
                upgradeDB.deleteObjectStore(store);
            }
        }
        for (let store of dbSchema.stores) {
            if (!upgradeDB.objectStoreNames.contains(store.name)) {
                console.debug(`[idb].[${upgradeDB.name}]: Adding store [${store.name}]`);
                IndexedDBManager.addNewStore(upgradeDB, store);
            }
            else {
                IndexedDBManager.upgradeExistingStore(upgradeDB, store, transaction);
            }
        }
    }
    static addNewStore(upgradeDB, store) {
        if (store.isKeyVal) {
            upgradeDB.createObjectStore(store.name);
            return;
        }
        let primaryKey = store.primaryKey;
        if (!primaryKey) {
            console.debug(`[idb].[${upgradeDB.name}]: No PK detected in store [${store.name}]. Creating default with keyPath 'id'`);
            primaryKey = { name: 'id', keyPath: 'id', auto: true };
        }
        const newStore = upgradeDB.createObjectStore(store.name, { keyPath: primaryKey.keyPath, autoIncrement: primaryKey.auto });
        for (const index of store.indexes) {
            newStore.createIndex(index.name, index.keyPath, { unique: index.unique, multiEntry: index.multiEntry });
        }
    }
    static upgradeExistingStore(upgradeDB, store, transaction) {
        const dbStore = transaction.objectStore(store.name);
        if (!dbStore.keyPath && !store.isKeyVal || dbStore.keyPath && dbStore.keyPath != store.primaryKey.keyPath) {
            console.debug(`[idb].[${upgradeDB.name}]: Significant change detected in store [${store.name}] requiring rebuild`);
            upgradeDB.deleteObjectStore(store.name);
            IndexedDBManager.addNewStore(upgradeDB, store);
            return;
        }
        const schemaIndexNames = getSchemaEntityNames(store.indexes);
        for (let index of dbStore.indexNames) {
            if (!schemaIndexNames.includes(index)) {
                console.debug(`[idb].[${upgradeDB.name}]: Dropping index [${store.name}].[${index}]`);
                dbStore.deleteIndex(index);
            }
        }
        for (let index of store.indexes) {
            if (!dbStore.indexNames.contains(index.name)) {
                console.debug(`[idb].[${upgradeDB.name}]: Adding index [${store.name}].[${index.name}]`);
                dbStore.createIndex(index.name, index.keyPath, { unique: index.unique, multiEntry: index.multiEntry });
            }
        }
    }
}
exports.IndexedDBManager = IndexedDBManager;
class IndexedDB {
    constructor(store, instance) {
        this._disposed = false;
        this.clearStore = (storeName) => __awaiter(this, void 0, void 0, function* () {
            yield this._instance.clear(storeName);
        });
        this.deleteStore = (storeName) => __awaiter(this, void 0, void 0, function* () {
            yield this._instance.deleteObjectStore(storeName);
        });
        this.add = (storeName, data) => __awaiter(this, void 0, void 0, function* () {
            yield this._instance.add(storeName, data);
        });
        this.put = (storeName, data, key) => __awaiter(this, void 0, void 0, function* () {
            yield this._instance.put(storeName, data, key);
        });
        this.putAll = (storeName, data) => __awaiter(this, void 0, void 0, function* () {
            const tx = this._instance.transaction(storeName, 'readwrite');
            for (const item of data) {
                yield tx.store.put(item);
            }
            yield tx.done;
        });
        this.delete = (storeName, key) => __awaiter(this, void 0, void 0, function* () {
            const eKey = IndexedDB.evaluateKey(key);
            if (Array.isArray(eKey)) {
                const tx = this._instance.transaction(storeName, 'readwrite');
                for (const k of eKey) {
                    yield tx.store.delete(k);
                }
                yield tx.done;
                return;
            }
            yield this._instance.delete(storeName, eKey);
        });
        this.get = (storeName, query, filters) => __awaiter(this, void 0, void 0, function* () {
            const filterFns = IndexedDB.evaluateFilters(filters);
            const key = IndexedDB.evaluateKey(query);
            if (key && !filterFns.length) {
                return yield this._instance.get(storeName, key);
            }
            let cursor = yield this._instance.transaction(storeName).store.openCursor(key);
            while (cursor) {
                const value = cursor.value;
                if (IndexedDB.isFiltered(value, filterFns)) {
                    return value;
                }
                cursor = yield cursor.continue();
            }
            return null;
        });
        this.getAll = (storeName, query, filters) => __awaiter(this, void 0, void 0, function* () {
            const filterFns = IndexedDB.evaluateFilters(filters);
            const key = IndexedDB.evaluateKey(query);
            if (!filterFns.length && !Array.isArray(key)) {
                return this._instance.getAll(storeName, key);
            }
            let records = [];
            if (Array.isArray(key)) {
                const store = yield this._instance.transaction(storeName).store;
                for (const k of key) {
                    const value = yield store.get(k);
                    if (value && IndexedDB.isFiltered(value, filterFns)) {
                        records.push(value);
                    }
                }
                return records;
            }
            let cursor = yield this._instance.transaction(storeName).store.openCursor(key);
            while (cursor) {
                const value = cursor.value;
                if (IndexedDB.isFiltered(value, filterFns)) {
                    records.push(value);
                }
                cursor = yield cursor.continue();
            }
            return records;
        });
        this.getFromIndex = (storeName, indexName, query, filters) => __awaiter(this, void 0, void 0, function* () {
            const filterFns = IndexedDB.evaluateFilters(filters);
            const key = IndexedDB.evaluateKey(query);
            if (!filterFns.length) {
                return yield this._instance.getFromIndex(storeName, indexName, key);
            }
            let cursor = yield this._instance.transaction(storeName).store.index(indexName).openCursor(key);
            while (cursor) {
                const value = cursor.value;
                if (IndexedDB.isFiltered(value, filterFns)) {
                    return value;
                }
                cursor = yield cursor.continue();
            }
            return null;
        });
        this.getAllFromIndex = (storeName, indexName, query, filters) => __awaiter(this, void 0, void 0, function* () {
            const filterFns = IndexedDB.evaluateFilters(filters);
            const key = IndexedDB.evaluateKey(query);
            if (!filterFns.length && !Array.isArray(key)) {
                return yield this._instance.getAllFromIndex(storeName, indexName, key);
            }
            let records = [];
            if (Array.isArray(key)) {
                const index = yield this._instance.transaction(storeName).store.index(indexName);
                for (const k of key) {
                    const values = yield index.getAll(k);
                    records = records.concat(values.filter((value) => IndexedDB.isFiltered(value, filterFns)));
                }
                return records;
            }
            let cursor = yield this._instance.transaction(storeName).store.index(indexName).openCursor(key);
            while (cursor) {
                const value = cursor.value;
                if (IndexedDB.isFiltered(value, filterFns)) {
                    records.push(value);
                }
                cursor = yield cursor.continue();
            }
            return records;
        });
        this.deleteAllFromIndex = (storeName, indexName, query, filters) => __awaiter(this, void 0, void 0, function* () {
            const filterFns = IndexedDB.evaluateFilters(filters);
            const key = IndexedDB.evaluateKey(query);
            const index = yield this._instance.transaction(storeName, 'readwrite').store.index(indexName);
            const keys = Array.isArray(key)
                ? key
                : [key];
            for (const k of keys) {
                let cursor = yield index.openCursor(k);
                while (cursor) {
                    const value = cursor.value;
                    if (IndexedDB.isFiltered(value, filterFns)) {
                        cursor.delete();
                    }
                    cursor = yield cursor.continue();
                }
            }
        });
        this.count = (storeName, key) => __awaiter(this, void 0, void 0, function* () {
            return yield this._instance.count(storeName, IndexedDB.evaluateKey(key));
        });
        this.countFromIndex = (storeName, indexName, key) => __awaiter(this, void 0, void 0, function* () {
            return yield this._instance.countFromIndex(storeName, indexName, IndexedDB.evaluateKey(key));
        });
        this.getKey = (storeName, query) => __awaiter(this, void 0, void 0, function* () {
            return yield this._instance.getKey(storeName, IndexedDB.evaluateKey(query));
        });
        this.getAllKeys = (storeName, query) => __awaiter(this, void 0, void 0, function* () {
            return this._instance.getAllKeys(storeName, IndexedDB.evaluateKey(query));
        });
        this.getKeyFromIndex = (storeName, indexName, query) => __awaiter(this, void 0, void 0, function* () {
            return yield this._instance.getKeyFromIndex(storeName, indexName, IndexedDB.evaluateKey(query));
        });
        this.getAllKeysFromIndex = (storeName, indexName, query) => __awaiter(this, void 0, void 0, function* () {
            return this._instance.getAllKeysFromIndex(storeName, indexName, IndexedDB.evaluateKey(query));
        });
        this.name = store.name;
        this.version = store.version;
        this._instance = instance;
    }
    dispose() {
        if (this._instance && !this._disposed) {
            this._instance.close();
            this._disposed = true;
        }
    }
    recycle(instance) {
        this.dispose();
        this._instance = instance;
        this._disposed = false;
    }
    static isKeyRange(key) {
        return typeof (key) === 'object' && ('lower' in key || 'upper' in key);
    }
    static isKeyCollection(key) {
        return Array.isArray(key) && key.length > 0 && typeof (key[0]) !== 'object';
    }
    static isFiltered(record, filters) {
        return filters.every((filter) => {
            return filter.call(this, record);
        });
    }
    static evaluateKey(key) {
        if (!key) {
            return key;
        }
        if (this.isKeyRange(key)) {
            if (key.lower && key.upper) {
                return key.lower === key.upper
                    ? IDBKeyRange.only(key.lower)
                    : IDBKeyRange.bound(key.lower, key.upper, key.lowerOpen, key.upperOpen);
            }
            return key.lower
                ? IDBKeyRange.lowerBound(key.lower, key.lowerOpen)
                : IDBKeyRange.upperBound(key.upper, key.upperOpen);
        }
        if (this.isKeyCollection(key)) {
            return key.length == 0
                ? null
                : key.length == 1
                    ? key[0]
                    : key;
        }
        return typeof (key) === 'object'
            ? null
            : key;
    }
    static evaluateFilters(filters) {
        if (!filters || !filters.length) {
            return [];
        }
        return filters.map((filter) => {
            try {
                return eval('(' + filter + ')');
            }
            catch (e) {
                console.error(`[idb]: Error evaluating filter '${filter}' as a function`);
            }
            return null;
        }).filter((fn) => {
            return typeof (fn) === "function";
        });
    }
}
exports.IndexedDB = IndexedDB;


/***/ })

/******/ });
/************************************************************************/
/******/ // The module cache
/******/ var __webpack_module_cache__ = {};
/******/ 
/******/ // The require function
/******/ function __webpack_require__(moduleId) {
/******/ 	// Check if module is in cache
/******/ 	var cachedModule = __webpack_module_cache__[moduleId];
/******/ 	if (cachedModule !== undefined) {
/******/ 		return cachedModule.exports;
/******/ 	}
/******/ 	// Create a new module (and put it into the cache)
/******/ 	var module = __webpack_module_cache__[moduleId] = {
/******/ 		// no module.id needed
/******/ 		// no module.loaded needed
/******/ 		exports: {}
/******/ 	};
/******/ 
/******/ 	// Execute the module function
/******/ 	__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 
/******/ 	// Return the exports of the module
/******/ 	return module.exports;
/******/ }
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
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;
/*!**************************!*\
  !*** ./Scripts/index.ts ***!
  \**************************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.createManager = void 0;
const interopClasses_1 = __webpack_require__(/*! ./interopClasses */ "./Scripts/interopClasses.ts");
function createManager() {
    return new interopClasses_1.IndexedDBManager();
}
exports.createManager = createManager;

})();

var __webpack_exports___esModule = __webpack_exports__.__esModule;
var __webpack_exports__createManager = __webpack_exports__.createManager;
export { __webpack_exports___esModule as __esModule, __webpack_exports__createManager as createManager };

//# sourceMappingURL=data:application/json;charset=utf-8;base64,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LEdBQUcsTUFBTSxHQUFHLEdBQUcsQ0FBQyxDQUFDO2FBQ25DO1lBQUMsT0FBTyxDQUFDLEVBQUU7Z0JBQ1IsT0FBTyxDQUFDLEtBQUssQ0FBQyxtQ0FBbUMsTUFBTSxpQkFBaUIsQ0FBQzthQUM1RTtZQUNELE9BQU8sSUFBSSxDQUFDO1FBQ2hCLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFO1lBQ2IsT0FBTyxPQUFNLENBQUMsRUFBRSxDQUFDLEtBQUssVUFBVSxDQUFDO1FBQ3JDLENBQUMsQ0FBQyxDQUFDO0lBQ1AsQ0FBQztDQUNKO0FBN1NELDhCQTZTQzs7Ozs7OztTQzdmRDtTQUNBOztTQUVBO1NBQ0E7U0FDQTtTQUNBO1NBQ0E7U0FDQTtTQUNBO1NBQ0E7U0FDQTtTQUNBO1NBQ0E7U0FDQTtTQUNBOztTQUVBO1NBQ0E7O1NBRUE7U0FDQTtTQUNBOzs7OztVQ3RCQTtVQUNBO1VBQ0E7VUFDQTtVQUNBLHlDQUF5Qyx3Q0FBd0M7VUFDakY7VUFDQTtVQUNBOzs7OztVQ1BBOzs7OztVQ0FBO1VBQ0E7VUFDQTtVQUNBLHVEQUF1RCxpQkFBaUI7VUFDeEU7VUFDQSxnREFBZ0QsYUFBYTtVQUM3RDs7Ozs7Ozs7Ozs7Ozs7QUNOQSxvR0FBb0Q7QUFFcEQsU0FBZ0IsYUFBYTtJQUN6QixPQUFPLElBQUksaUNBQWdCLEVBQUUsQ0FBQztBQUNsQyxDQUFDO0FBRkQsc0NBRUMiLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly9tdC5ibGF6b3IuaWRiLy4vbm9kZV9tb2R1bGVzL2lkYi9idWlsZC9lc20vaW5kZXguanMiLCJ3ZWJwYWNrOi8vbXQuYmxhem9yLmlkYi8uL25vZGVfbW9kdWxlcy9pZGIvYnVpbGQvZXNtL3dyYXAtaWRiLXZhbHVlLmpzIiwid2VicGFjazovL210LmJsYXpvci5pZGIvLi9TY3JpcHRzL2ludGVyb3BDbGFzc2VzLnRzIiwid2VicGFjazovL210LmJsYXpvci5pZGIvd2VicGFjay9ib290c3RyYXAiLCJ3ZWJwYWNrOi8vbXQuYmxhem9yLmlkYi93ZWJwYWNrL3J1bnRpbWUvZGVmaW5lIHByb3BlcnR5IGdldHRlcnMiLCJ3ZWJwYWNrOi8vbXQuYmxhem9yLmlkYi93ZWJwYWNrL3J1bnRpbWUvaGFzT3duUHJvcGVydHkgc2hvcnRoYW5kIiwid2VicGFjazovL210LmJsYXpvci5pZGIvd2VicGFjay9ydW50aW1lL21ha2UgbmFtZXNwYWNlIG9iamVjdCIsIndlYnBhY2s6Ly9tdC5ibGF6b3IuaWRiLy4vU2NyaXB0cy9pbmRleC50cyJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyB3IGFzIHdyYXAsIHIgYXMgcmVwbGFjZVRyYXBzIH0gZnJvbSAnLi93cmFwLWlkYi12YWx1ZS5qcyc7XG5leHBvcnQgeyB1IGFzIHVud3JhcCwgdyBhcyB3cmFwIH0gZnJvbSAnLi93cmFwLWlkYi12YWx1ZS5qcyc7XG5cbi8qKlxuICogT3BlbiBhIGRhdGFiYXNlLlxuICpcbiAqIEBwYXJhbSBuYW1lIE5hbWUgb2YgdGhlIGRhdGFiYXNlLlxuICogQHBhcmFtIHZlcnNpb24gU2NoZW1hIHZlcnNpb24uXG4gKiBAcGFyYW0gY2FsbGJhY2tzIEFkZGl0aW9uYWwgY2FsbGJhY2tzLlxuICovXG5mdW5jdGlvbiBvcGVuREIobmFtZSwgdmVyc2lvbiwgeyBibG9ja2VkLCB1cGdyYWRlLCBibG9ja2luZywgdGVybWluYXRlZCB9ID0ge30pIHtcbiAgICBjb25zdCByZXF1ZXN0ID0gaW5kZXhlZERCLm9wZW4obmFtZSwgdmVyc2lvbik7XG4gICAgY29uc3Qgb3BlblByb21pc2UgPSB3cmFwKHJlcXVlc3QpO1xuICAgIGlmICh1cGdyYWRlKSB7XG4gICAgICAgIHJlcXVlc3QuYWRkRXZlbnRMaXN0ZW5lcigndXBncmFkZW5lZWRlZCcsIChldmVudCkgPT4ge1xuICAgICAgICAgICAgdXBncmFkZSh3cmFwKHJlcXVlc3QucmVzdWx0KSwgZXZlbnQub2xkVmVyc2lvbiwgZXZlbnQubmV3VmVyc2lvbiwgd3JhcChyZXF1ZXN0LnRyYW5zYWN0aW9uKSk7XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICBpZiAoYmxvY2tlZClcbiAgICAgICAgcmVxdWVzdC5hZGRFdmVudExpc3RlbmVyKCdibG9ja2VkJywgKCkgPT4gYmxvY2tlZCgpKTtcbiAgICBvcGVuUHJvbWlzZVxuICAgICAgICAudGhlbigoZGIpID0+IHtcbiAgICAgICAgaWYgKHRlcm1pbmF0ZWQpXG4gICAgICAgICAgICBkYi5hZGRFdmVudExpc3RlbmVyKCdjbG9zZScsICgpID0+IHRlcm1pbmF0ZWQoKSk7XG4gICAgICAgIGlmIChibG9ja2luZylcbiAgICAgICAgICAgIGRiLmFkZEV2ZW50TGlzdGVuZXIoJ3ZlcnNpb25jaGFuZ2UnLCAoKSA9PiBibG9ja2luZygpKTtcbiAgICB9KVxuICAgICAgICAuY2F0Y2goKCkgPT4geyB9KTtcbiAgICByZXR1cm4gb3BlblByb21pc2U7XG59XG4vKipcbiAqIERlbGV0ZSBhIGRhdGFiYXNlLlxuICpcbiAqIEBwYXJhbSBuYW1lIE5hbWUgb2YgdGhlIGRhdGFiYXNlLlxuICovXG5mdW5jdGlvbiBkZWxldGVEQihuYW1lLCB7IGJsb2NrZWQgfSA9IHt9KSB7XG4gICAgY29uc3QgcmVxdWVzdCA9IGluZGV4ZWREQi5kZWxldGVEYXRhYmFzZShuYW1lKTtcbiAgICBpZiAoYmxvY2tlZClcbiAgICAgICAgcmVxdWVzdC5hZGRFdmVudExpc3RlbmVyKCdibG9ja2VkJywgKCkgPT4gYmxvY2tlZCgpKTtcbiAgICByZXR1cm4gd3JhcChyZXF1ZXN0KS50aGVuKCgpID0+IHVuZGVmaW5lZCk7XG59XG5cbmNvbnN0IHJlYWRNZXRob2RzID0gWydnZXQnLCAnZ2V0S2V5JywgJ2dldEFsbCcsICdnZXRBbGxLZXlzJywgJ2NvdW50J107XG5jb25zdCB3cml0ZU1ldGhvZHMgPSBbJ3B1dCcsICdhZGQnLCAnZGVsZXRlJywgJ2NsZWFyJ107XG5jb25zdCBjYWNoZWRNZXRob2RzID0gbmV3IE1hcCgpO1xuZnVuY3Rpb24gZ2V0TWV0aG9kKHRhcmdldCwgcHJvcCkge1xuICAgIGlmICghKHRhcmdldCBpbnN0YW5jZW9mIElEQkRhdGFiYXNlICYmXG4gICAgICAgICEocHJvcCBpbiB0YXJnZXQpICYmXG4gICAgICAgIHR5cGVvZiBwcm9wID09PSAnc3RyaW5nJykpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAoY2FjaGVkTWV0aG9kcy5nZXQocHJvcCkpXG4gICAgICAgIHJldHVybiBjYWNoZWRNZXRob2RzLmdldChwcm9wKTtcbiAgICBjb25zdCB0YXJnZXRGdW5jTmFtZSA9IHByb3AucmVwbGFjZSgvRnJvbUluZGV4JC8sICcnKTtcbiAgICBjb25zdCB1c2VJbmRleCA9IHByb3AgIT09IHRhcmdldEZ1bmNOYW1lO1xuICAgIGNvbnN0IGlzV3JpdGUgPSB3cml0ZU1ldGhvZHMuaW5jbHVkZXModGFyZ2V0RnVuY05hbWUpO1xuICAgIGlmIChcbiAgICAvLyBCYWlsIGlmIHRoZSB0YXJnZXQgZG9lc24ndCBleGlzdCBvbiB0aGUgdGFyZ2V0LiBFZywgZ2V0QWxsIGlzbid0IGluIEVkZ2UuXG4gICAgISh0YXJnZXRGdW5jTmFtZSBpbiAodXNlSW5kZXggPyBJREJJbmRleCA6IElEQk9iamVjdFN0b3JlKS5wcm90b3R5cGUpIHx8XG4gICAgICAgICEoaXNXcml0ZSB8fCByZWFkTWV0aG9kcy5pbmNsdWRlcyh0YXJnZXRGdW5jTmFtZSkpKSB7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG4gICAgY29uc3QgbWV0aG9kID0gYXN5bmMgZnVuY3Rpb24gKHN0b3JlTmFtZSwgLi4uYXJncykge1xuICAgICAgICAvLyBpc1dyaXRlID8gJ3JlYWR3cml0ZScgOiB1bmRlZmluZWQgZ3ppcHBzIGJldHRlciwgYnV0IGZhaWxzIGluIEVkZ2UgOihcbiAgICAgICAgY29uc3QgdHggPSB0aGlzLnRyYW5zYWN0aW9uKHN0b3JlTmFtZSwgaXNXcml0ZSA/ICdyZWFkd3JpdGUnIDogJ3JlYWRvbmx5Jyk7XG4gICAgICAgIGxldCB0YXJnZXQgPSB0eC5zdG9yZTtcbiAgICAgICAgaWYgKHVzZUluZGV4KVxuICAgICAgICAgICAgdGFyZ2V0ID0gdGFyZ2V0LmluZGV4KGFyZ3Muc2hpZnQoKSk7XG4gICAgICAgIC8vIE11c3QgcmVqZWN0IGlmIG9wIHJlamVjdHMuXG4gICAgICAgIC8vIElmIGl0J3MgYSB3cml0ZSBvcGVyYXRpb24sIG11c3QgcmVqZWN0IGlmIHR4LmRvbmUgcmVqZWN0cy5cbiAgICAgICAgLy8gTXVzdCByZWplY3Qgd2l0aCBvcCByZWplY3Rpb24gZmlyc3QuXG4gICAgICAgIC8vIE11c3QgcmVzb2x2ZSB3aXRoIG9wIHZhbHVlLlxuICAgICAgICAvLyBNdXN0IGhhbmRsZSBib3RoIHByb21pc2VzIChubyB1bmhhbmRsZWQgcmVqZWN0aW9ucylcbiAgICAgICAgcmV0dXJuIChhd2FpdCBQcm9taXNlLmFsbChbXG4gICAgICAgICAgICB0YXJnZXRbdGFyZ2V0RnVuY05hbWVdKC4uLmFyZ3MpLFxuICAgICAgICAgICAgaXNXcml0ZSAmJiB0eC5kb25lLFxuICAgICAgICBdKSlbMF07XG4gICAgfTtcbiAgICBjYWNoZWRNZXRob2RzLnNldChwcm9wLCBtZXRob2QpO1xuICAgIHJldHVybiBtZXRob2Q7XG59XG5yZXBsYWNlVHJhcHMoKG9sZFRyYXBzKSA9PiAoe1xuICAgIC4uLm9sZFRyYXBzLFxuICAgIGdldDogKHRhcmdldCwgcHJvcCwgcmVjZWl2ZXIpID0+IGdldE1ldGhvZCh0YXJnZXQsIHByb3ApIHx8IG9sZFRyYXBzLmdldCh0YXJnZXQsIHByb3AsIHJlY2VpdmVyKSxcbiAgICBoYXM6ICh0YXJnZXQsIHByb3ApID0+ICEhZ2V0TWV0aG9kKHRhcmdldCwgcHJvcCkgfHwgb2xkVHJhcHMuaGFzKHRhcmdldCwgcHJvcCksXG59KSk7XG5cbmV4cG9ydCB7IGRlbGV0ZURCLCBvcGVuREIgfTtcbiIsImNvbnN0IGluc3RhbmNlT2ZBbnkgPSAob2JqZWN0LCBjb25zdHJ1Y3RvcnMpID0+IGNvbnN0cnVjdG9ycy5zb21lKChjKSA9PiBvYmplY3QgaW5zdGFuY2VvZiBjKTtcblxubGV0IGlkYlByb3h5YWJsZVR5cGVzO1xubGV0IGN1cnNvckFkdmFuY2VNZXRob2RzO1xuLy8gVGhpcyBpcyBhIGZ1bmN0aW9uIHRvIHByZXZlbnQgaXQgdGhyb3dpbmcgdXAgaW4gbm9kZSBlbnZpcm9ubWVudHMuXG5mdW5jdGlvbiBnZXRJZGJQcm94eWFibGVUeXBlcygpIHtcbiAgICByZXR1cm4gKGlkYlByb3h5YWJsZVR5cGVzIHx8XG4gICAgICAgIChpZGJQcm94eWFibGVUeXBlcyA9IFtcbiAgICAgICAgICAgIElEQkRhdGFiYXNlLFxuICAgICAgICAgICAgSURCT2JqZWN0U3RvcmUsXG4gICAgICAgICAgICBJREJJbmRleCxcbiAgICAgICAgICAgIElEQkN1cnNvcixcbiAgICAgICAgICAgIElEQlRyYW5zYWN0aW9uLFxuICAgICAgICBdKSk7XG59XG4vLyBUaGlzIGlzIGEgZnVuY3Rpb24gdG8gcHJldmVudCBpdCB0aHJvd2luZyB1cCBpbiBub2RlIGVudmlyb25tZW50cy5cbmZ1bmN0aW9uIGdldEN1cnNvckFkdmFuY2VNZXRob2RzKCkge1xuICAgIHJldHVybiAoY3Vyc29yQWR2YW5jZU1ldGhvZHMgfHxcbiAgICAgICAgKGN1cnNvckFkdmFuY2VNZXRob2RzID0gW1xuICAgICAgICAgICAgSURCQ3Vyc29yLnByb3RvdHlwZS5hZHZhbmNlLFxuICAgICAgICAgICAgSURCQ3Vyc29yLnByb3RvdHlwZS5jb250aW51ZSxcbiAgICAgICAgICAgIElEQkN1cnNvci5wcm90b3R5cGUuY29udGludWVQcmltYXJ5S2V5LFxuICAgICAgICBdKSk7XG59XG5jb25zdCBjdXJzb3JSZXF1ZXN0TWFwID0gbmV3IFdlYWtNYXAoKTtcbmNvbnN0IHRyYW5zYWN0aW9uRG9uZU1hcCA9IG5ldyBXZWFrTWFwKCk7XG5jb25zdCB0cmFuc2FjdGlvblN0b3JlTmFtZXNNYXAgPSBuZXcgV2Vha01hcCgpO1xuY29uc3QgdHJhbnNmb3JtQ2FjaGUgPSBuZXcgV2Vha01hcCgpO1xuY29uc3QgcmV2ZXJzZVRyYW5zZm9ybUNhY2hlID0gbmV3IFdlYWtNYXAoKTtcbmZ1bmN0aW9uIHByb21pc2lmeVJlcXVlc3QocmVxdWVzdCkge1xuICAgIGNvbnN0IHByb21pc2UgPSBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgIGNvbnN0IHVubGlzdGVuID0gKCkgPT4ge1xuICAgICAgICAgICAgcmVxdWVzdC5yZW1vdmVFdmVudExpc3RlbmVyKCdzdWNjZXNzJywgc3VjY2Vzcyk7XG4gICAgICAgICAgICByZXF1ZXN0LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ2Vycm9yJywgZXJyb3IpO1xuICAgICAgICB9O1xuICAgICAgICBjb25zdCBzdWNjZXNzID0gKCkgPT4ge1xuICAgICAgICAgICAgcmVzb2x2ZSh3cmFwKHJlcXVlc3QucmVzdWx0KSk7XG4gICAgICAgICAgICB1bmxpc3RlbigpO1xuICAgICAgICB9O1xuICAgICAgICBjb25zdCBlcnJvciA9ICgpID0+IHtcbiAgICAgICAgICAgIHJlamVjdChyZXF1ZXN0LmVycm9yKTtcbiAgICAgICAgICAgIHVubGlzdGVuKCk7XG4gICAgICAgIH07XG4gICAgICAgIHJlcXVlc3QuYWRkRXZlbnRMaXN0ZW5lcignc3VjY2VzcycsIHN1Y2Nlc3MpO1xuICAgICAgICByZXF1ZXN0LmFkZEV2ZW50TGlzdGVuZXIoJ2Vycm9yJywgZXJyb3IpO1xuICAgIH0pO1xuICAgIHByb21pc2VcbiAgICAgICAgLnRoZW4oKHZhbHVlKSA9PiB7XG4gICAgICAgIC8vIFNpbmNlIGN1cnNvcmluZyByZXVzZXMgdGhlIElEQlJlcXVlc3QgKCpzaWdoKiksIHdlIGNhY2hlIGl0IGZvciBsYXRlciByZXRyaWV2YWxcbiAgICAgICAgLy8gKHNlZSB3cmFwRnVuY3Rpb24pLlxuICAgICAgICBpZiAodmFsdWUgaW5zdGFuY2VvZiBJREJDdXJzb3IpIHtcbiAgICAgICAgICAgIGN1cnNvclJlcXVlc3RNYXAuc2V0KHZhbHVlLCByZXF1ZXN0KTtcbiAgICAgICAgfVxuICAgICAgICAvLyBDYXRjaGluZyB0byBhdm9pZCBcIlVuY2F1Z2h0IFByb21pc2UgZXhjZXB0aW9uc1wiXG4gICAgfSlcbiAgICAgICAgLmNhdGNoKCgpID0+IHsgfSk7XG4gICAgLy8gVGhpcyBtYXBwaW5nIGV4aXN0cyBpbiByZXZlcnNlVHJhbnNmb3JtQ2FjaGUgYnV0IGRvZXNuJ3QgZG9lc24ndCBleGlzdCBpbiB0cmFuc2Zvcm1DYWNoZS4gVGhpc1xuICAgIC8vIGlzIGJlY2F1c2Ugd2UgY3JlYXRlIG1hbnkgcHJvbWlzZXMgZnJvbSBhIHNpbmdsZSBJREJSZXF1ZXN0LlxuICAgIHJldmVyc2VUcmFuc2Zvcm1DYWNoZS5zZXQocHJvbWlzZSwgcmVxdWVzdCk7XG4gICAgcmV0dXJuIHByb21pc2U7XG59XG5mdW5jdGlvbiBjYWNoZURvbmVQcm9taXNlRm9yVHJhbnNhY3Rpb24odHgpIHtcbiAgICAvLyBFYXJseSBiYWlsIGlmIHdlJ3ZlIGFscmVhZHkgY3JlYXRlZCBhIGRvbmUgcHJvbWlzZSBmb3IgdGhpcyB0cmFuc2FjdGlvbi5cbiAgICBpZiAodHJhbnNhY3Rpb25Eb25lTWFwLmhhcyh0eCkpXG4gICAgICAgIHJldHVybjtcbiAgICBjb25zdCBkb25lID0gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICBjb25zdCB1bmxpc3RlbiA9ICgpID0+IHtcbiAgICAgICAgICAgIHR4LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ2NvbXBsZXRlJywgY29tcGxldGUpO1xuICAgICAgICAgICAgdHgucmVtb3ZlRXZlbnRMaXN0ZW5lcignZXJyb3InLCBlcnJvcik7XG4gICAgICAgICAgICB0eC5yZW1vdmVFdmVudExpc3RlbmVyKCdhYm9ydCcsIGVycm9yKTtcbiAgICAgICAgfTtcbiAgICAgICAgY29uc3QgY29tcGxldGUgPSAoKSA9PiB7XG4gICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgICAgICB1bmxpc3RlbigpO1xuICAgICAgICB9O1xuICAgICAgICBjb25zdCBlcnJvciA9ICgpID0+IHtcbiAgICAgICAgICAgIHJlamVjdCh0eC5lcnJvciB8fCBuZXcgRE9NRXhjZXB0aW9uKCdBYm9ydEVycm9yJywgJ0Fib3J0RXJyb3InKSk7XG4gICAgICAgICAgICB1bmxpc3RlbigpO1xuICAgICAgICB9O1xuICAgICAgICB0eC5hZGRFdmVudExpc3RlbmVyKCdjb21wbGV0ZScsIGNvbXBsZXRlKTtcbiAgICAgICAgdHguYWRkRXZlbnRMaXN0ZW5lcignZXJyb3InLCBlcnJvcik7XG4gICAgICAgIHR4LmFkZEV2ZW50TGlzdGVuZXIoJ2Fib3J0JywgZXJyb3IpO1xuICAgIH0pO1xuICAgIC8vIENhY2hlIGl0IGZvciBsYXRlciByZXRyaWV2YWwuXG4gICAgdHJhbnNhY3Rpb25Eb25lTWFwLnNldCh0eCwgZG9uZSk7XG59XG5sZXQgaWRiUHJveHlUcmFwcyA9IHtcbiAgICBnZXQodGFyZ2V0LCBwcm9wLCByZWNlaXZlcikge1xuICAgICAgICBpZiAodGFyZ2V0IGluc3RhbmNlb2YgSURCVHJhbnNhY3Rpb24pIHtcbiAgICAgICAgICAgIC8vIFNwZWNpYWwgaGFuZGxpbmcgZm9yIHRyYW5zYWN0aW9uLmRvbmUuXG4gICAgICAgICAgICBpZiAocHJvcCA9PT0gJ2RvbmUnKVxuICAgICAgICAgICAgICAgIHJldHVybiB0cmFuc2FjdGlvbkRvbmVNYXAuZ2V0KHRhcmdldCk7XG4gICAgICAgICAgICAvLyBQb2x5ZmlsbCBmb3Igb2JqZWN0U3RvcmVOYW1lcyBiZWNhdXNlIG9mIEVkZ2UuXG4gICAgICAgICAgICBpZiAocHJvcCA9PT0gJ29iamVjdFN0b3JlTmFtZXMnKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRhcmdldC5vYmplY3RTdG9yZU5hbWVzIHx8IHRyYW5zYWN0aW9uU3RvcmVOYW1lc01hcC5nZXQodGFyZ2V0KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIC8vIE1ha2UgdHguc3RvcmUgcmV0dXJuIHRoZSBvbmx5IHN0b3JlIGluIHRoZSB0cmFuc2FjdGlvbiwgb3IgdW5kZWZpbmVkIGlmIHRoZXJlIGFyZSBtYW55LlxuICAgICAgICAgICAgaWYgKHByb3AgPT09ICdzdG9yZScpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVjZWl2ZXIub2JqZWN0U3RvcmVOYW1lc1sxXVxuICAgICAgICAgICAgICAgICAgICA/IHVuZGVmaW5lZFxuICAgICAgICAgICAgICAgICAgICA6IHJlY2VpdmVyLm9iamVjdFN0b3JlKHJlY2VpdmVyLm9iamVjdFN0b3JlTmFtZXNbMF0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIC8vIEVsc2UgdHJhbnNmb3JtIHdoYXRldmVyIHdlIGdldCBiYWNrLlxuICAgICAgICByZXR1cm4gd3JhcCh0YXJnZXRbcHJvcF0pO1xuICAgIH0sXG4gICAgc2V0KHRhcmdldCwgcHJvcCwgdmFsdWUpIHtcbiAgICAgICAgdGFyZ2V0W3Byb3BdID0gdmFsdWU7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH0sXG4gICAgaGFzKHRhcmdldCwgcHJvcCkge1xuICAgICAgICBpZiAodGFyZ2V0IGluc3RhbmNlb2YgSURCVHJhbnNhY3Rpb24gJiZcbiAgICAgICAgICAgIChwcm9wID09PSAnZG9uZScgfHwgcHJvcCA9PT0gJ3N0b3JlJykpIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBwcm9wIGluIHRhcmdldDtcbiAgICB9LFxufTtcbmZ1bmN0aW9uIHJlcGxhY2VUcmFwcyhjYWxsYmFjaykge1xuICAgIGlkYlByb3h5VHJhcHMgPSBjYWxsYmFjayhpZGJQcm94eVRyYXBzKTtcbn1cbmZ1bmN0aW9uIHdyYXBGdW5jdGlvbihmdW5jKSB7XG4gICAgLy8gRHVlIHRvIGV4cGVjdGVkIG9iamVjdCBlcXVhbGl0eSAod2hpY2ggaXMgZW5mb3JjZWQgYnkgdGhlIGNhY2hpbmcgaW4gYHdyYXBgKSwgd2VcbiAgICAvLyBvbmx5IGNyZWF0ZSBvbmUgbmV3IGZ1bmMgcGVyIGZ1bmMuXG4gICAgLy8gRWRnZSBkb2Vzbid0IHN1cHBvcnQgb2JqZWN0U3RvcmVOYW1lcyAoYm9vbyksIHNvIHdlIHBvbHlmaWxsIGl0IGhlcmUuXG4gICAgaWYgKGZ1bmMgPT09IElEQkRhdGFiYXNlLnByb3RvdHlwZS50cmFuc2FjdGlvbiAmJlxuICAgICAgICAhKCdvYmplY3RTdG9yZU5hbWVzJyBpbiBJREJUcmFuc2FjdGlvbi5wcm90b3R5cGUpKSB7XG4gICAgICAgIHJldHVybiBmdW5jdGlvbiAoc3RvcmVOYW1lcywgLi4uYXJncykge1xuICAgICAgICAgICAgY29uc3QgdHggPSBmdW5jLmNhbGwodW53cmFwKHRoaXMpLCBzdG9yZU5hbWVzLCAuLi5hcmdzKTtcbiAgICAgICAgICAgIHRyYW5zYWN0aW9uU3RvcmVOYW1lc01hcC5zZXQodHgsIHN0b3JlTmFtZXMuc29ydCA/IHN0b3JlTmFtZXMuc29ydCgpIDogW3N0b3JlTmFtZXNdKTtcbiAgICAgICAgICAgIHJldHVybiB3cmFwKHR4KTtcbiAgICAgICAgfTtcbiAgICB9XG4gICAgLy8gQ3Vyc29yIG1ldGhvZHMgYXJlIHNwZWNpYWwsIGFzIHRoZSBiZWhhdmlvdXIgaXMgYSBsaXR0bGUgbW9yZSBkaWZmZXJlbnQgdG8gc3RhbmRhcmQgSURCLiBJblxuICAgIC8vIElEQiwgeW91IGFkdmFuY2UgdGhlIGN1cnNvciBhbmQgd2FpdCBmb3IgYSBuZXcgJ3N1Y2Nlc3MnIG9uIHRoZSBJREJSZXF1ZXN0IHRoYXQgZ2F2ZSB5b3UgdGhlXG4gICAgLy8gY3Vyc29yLiBJdCdzIGtpbmRhIGxpa2UgYSBwcm9taXNlIHRoYXQgY2FuIHJlc29sdmUgd2l0aCBtYW55IHZhbHVlcy4gVGhhdCBkb2Vzbid0IG1ha2Ugc2Vuc2VcbiAgICAvLyB3aXRoIHJlYWwgcHJvbWlzZXMsIHNvIGVhY2ggYWR2YW5jZSBtZXRob2RzIHJldHVybnMgYSBuZXcgcHJvbWlzZSBmb3IgdGhlIGN1cnNvciBvYmplY3QsIG9yXG4gICAgLy8gdW5kZWZpbmVkIGlmIHRoZSBlbmQgb2YgdGhlIGN1cnNvciBoYXMgYmVlbiByZWFjaGVkLlxuICAgIGlmIChnZXRDdXJzb3JBZHZhbmNlTWV0aG9kcygpLmluY2x1ZGVzKGZ1bmMpKSB7XG4gICAgICAgIHJldHVybiBmdW5jdGlvbiAoLi4uYXJncykge1xuICAgICAgICAgICAgLy8gQ2FsbGluZyB0aGUgb3JpZ2luYWwgZnVuY3Rpb24gd2l0aCB0aGUgcHJveHkgYXMgJ3RoaXMnIGNhdXNlcyBJTExFR0FMIElOVk9DQVRJT04sIHNvIHdlIHVzZVxuICAgICAgICAgICAgLy8gdGhlIG9yaWdpbmFsIG9iamVjdC5cbiAgICAgICAgICAgIGZ1bmMuYXBwbHkodW53cmFwKHRoaXMpLCBhcmdzKTtcbiAgICAgICAgICAgIHJldHVybiB3cmFwKGN1cnNvclJlcXVlc3RNYXAuZ2V0KHRoaXMpKTtcbiAgICAgICAgfTtcbiAgICB9XG4gICAgcmV0dXJuIGZ1bmN0aW9uICguLi5hcmdzKSB7XG4gICAgICAgIC8vIENhbGxpbmcgdGhlIG9yaWdpbmFsIGZ1bmN0aW9uIHdpdGggdGhlIHByb3h5IGFzICd0aGlzJyBjYXVzZXMgSUxMRUdBTCBJTlZPQ0FUSU9OLCBzbyB3ZSB1c2VcbiAgICAgICAgLy8gdGhlIG9yaWdpbmFsIG9iamVjdC5cbiAgICAgICAgcmV0dXJuIHdyYXAoZnVuYy5hcHBseSh1bndyYXAodGhpcyksIGFyZ3MpKTtcbiAgICB9O1xufVxuZnVuY3Rpb24gdHJhbnNmb3JtQ2FjaGFibGVWYWx1ZSh2YWx1ZSkge1xuICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdmdW5jdGlvbicpXG4gICAgICAgIHJldHVybiB3cmFwRnVuY3Rpb24odmFsdWUpO1xuICAgIC8vIFRoaXMgZG9lc24ndCByZXR1cm4sIGl0IGp1c3QgY3JlYXRlcyBhICdkb25lJyBwcm9taXNlIGZvciB0aGUgdHJhbnNhY3Rpb24sXG4gICAgLy8gd2hpY2ggaXMgbGF0ZXIgcmV0dXJuZWQgZm9yIHRyYW5zYWN0aW9uLmRvbmUgKHNlZSBpZGJPYmplY3RIYW5kbGVyKS5cbiAgICBpZiAodmFsdWUgaW5zdGFuY2VvZiBJREJUcmFuc2FjdGlvbilcbiAgICAgICAgY2FjaGVEb25lUHJvbWlzZUZvclRyYW5zYWN0aW9uKHZhbHVlKTtcbiAgICBpZiAoaW5zdGFuY2VPZkFueSh2YWx1ZSwgZ2V0SWRiUHJveHlhYmxlVHlwZXMoKSkpXG4gICAgICAgIHJldHVybiBuZXcgUHJveHkodmFsdWUsIGlkYlByb3h5VHJhcHMpO1xuICAgIC8vIFJldHVybiB0aGUgc2FtZSB2YWx1ZSBiYWNrIGlmIHdlJ3JlIG5vdCBnb2luZyB0byB0cmFuc2Zvcm0gaXQuXG4gICAgcmV0dXJuIHZhbHVlO1xufVxuZnVuY3Rpb24gd3JhcCh2YWx1ZSkge1xuICAgIC8vIFdlIHNvbWV0aW1lcyBnZW5lcmF0ZSBtdWx0aXBsZSBwcm9taXNlcyBmcm9tIGEgc2luZ2xlIElEQlJlcXVlc3QgKGVnIHdoZW4gY3Vyc29yaW5nKSwgYmVjYXVzZVxuICAgIC8vIElEQiBpcyB3ZWlyZCBhbmQgYSBzaW5nbGUgSURCUmVxdWVzdCBjYW4geWllbGQgbWFueSByZXNwb25zZXMsIHNvIHRoZXNlIGNhbid0IGJlIGNhY2hlZC5cbiAgICBpZiAodmFsdWUgaW5zdGFuY2VvZiBJREJSZXF1ZXN0KVxuICAgICAgICByZXR1cm4gcHJvbWlzaWZ5UmVxdWVzdCh2YWx1ZSk7XG4gICAgLy8gSWYgd2UndmUgYWxyZWFkeSB0cmFuc2Zvcm1lZCB0aGlzIHZhbHVlIGJlZm9yZSwgcmV1c2UgdGhlIHRyYW5zZm9ybWVkIHZhbHVlLlxuICAgIC8vIFRoaXMgaXMgZmFzdGVyLCBidXQgaXQgYWxzbyBwcm92aWRlcyBvYmplY3QgZXF1YWxpdHkuXG4gICAgaWYgKHRyYW5zZm9ybUNhY2hlLmhhcyh2YWx1ZSkpXG4gICAgICAgIHJldHVybiB0cmFuc2Zvcm1DYWNoZS5nZXQodmFsdWUpO1xuICAgIGNvbnN0IG5ld1ZhbHVlID0gdHJhbnNmb3JtQ2FjaGFibGVWYWx1ZSh2YWx1ZSk7XG4gICAgLy8gTm90IGFsbCB0eXBlcyBhcmUgdHJhbnNmb3JtZWQuXG4gICAgLy8gVGhlc2UgbWF5IGJlIHByaW1pdGl2ZSB0eXBlcywgc28gdGhleSBjYW4ndCBiZSBXZWFrTWFwIGtleXMuXG4gICAgaWYgKG5ld1ZhbHVlICE9PSB2YWx1ZSkge1xuICAgICAgICB0cmFuc2Zvcm1DYWNoZS5zZXQodmFsdWUsIG5ld1ZhbHVlKTtcbiAgICAgICAgcmV2ZXJzZVRyYW5zZm9ybUNhY2hlLnNldChuZXdWYWx1ZSwgdmFsdWUpO1xuICAgIH1cbiAgICByZXR1cm4gbmV3VmFsdWU7XG59XG5jb25zdCB1bndyYXAgPSAodmFsdWUpID0+IHJldmVyc2VUcmFuc2Zvcm1DYWNoZS5nZXQodmFsdWUpO1xuXG5leHBvcnQgeyByZXZlcnNlVHJhbnNmb3JtQ2FjaGUgYXMgYSwgaW5zdGFuY2VPZkFueSBhcyBpLCByZXBsYWNlVHJhcHMgYXMgciwgdW53cmFwIGFzIHUsIHdyYXAgYXMgdyB9O1xuIiwiaW1wb3J0IHtJREJQRGF0YWJhc2UsIG9wZW5EQiwgZGVsZXRlREIsIElEQlBUcmFuc2FjdGlvbiwgU3RvcmVOYW1lc30gZnJvbSAnaWRiJztcclxuaW1wb3J0IHtcclxuICAgIElEYkluZm9ybWF0aW9uLFxyXG4gICAgSURiU2NoZW1hLCBJS2V5UmFuZ2UsXHJcbiAgICBJU3RvcmVTY2hlbWFcclxufSBmcm9tICcuL2ludGVyb3BJbnRlcmZhY2VzJztcclxuXHJcbmxldCBnZXRTY2hlbWFFbnRpdHlOYW1lcyA9IChsaXN0OiBhbnlbXSk6IHN0cmluZ1tdID0+IHtcclxuICAgIGxldCBuYW1lczogc3RyaW5nW10gPSBbXTtcclxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGlzdC5sZW5ndGg7IGkrKykge1xyXG4gICAgICAgIG5hbWVzLnB1c2gobGlzdFtpXS5uYW1lKTtcclxuICAgIH1cclxuICAgIHJldHVybiBuYW1lcztcclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIEluZGV4ZWREQk1hbmFnZXIge1xyXG4gICAgcHJpdmF0ZSBfZGJJbnN0YW5jZXM6TWFwPHN0cmluZywgSW5kZXhlZERCPiA9IG5ldyBNYXA8c3RyaW5nLCBJbmRleGVkREI+KCk7XHJcblxyXG4gICAgcHVibGljIG9wZW5EYiA9IGFzeW5jIChkYlNjaGVtYTogSURiU2NoZW1hKTogUHJvbWlzZTxJbmRleGVkREI+ID0+IHtcclxuICAgICAgICBsZXQgZGI7XHJcbiAgICAgICAgXHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgZGIgPSB0aGlzLl9kYkluc3RhbmNlcy5nZXQoZGJTY2hlbWEubmFtZSk7XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBpZiAoIWRiIHx8IGRiLnZlcnNpb24gPCBkYlNjaGVtYS52ZXJzaW9uKSB7XHJcbiAgICAgICAgICAgICAgICBpZiAoZGIpIHtcclxuICAgICAgICAgICAgICAgICAgICBkYi5kaXNwb3NlKCk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIGRiID0gbmV3IEluZGV4ZWREQihkYlNjaGVtYSwgYXdhaXQgb3BlbkRCKGRiU2NoZW1hLm5hbWUsIGRiU2NoZW1hLnZlcnNpb24sIHtcclxuICAgICAgICAgICAgICAgICAgICB1cGdyYWRlKGRiLCBvbGRWZXJzaW9uLCBuZXdWZXJzaW9uLCB0cmFuc2FjdGlvbikge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKGBbaWRiXS5bJHtkYlNjaGVtYS5uYW1lfV06IERlcGxveWluZyBzY2hlbWEgY2hhbmdlcyBmcm9tICR7b2xkVmVyc2lvbn0gdG8gJHtuZXdWZXJzaW9ufWAsIGRiU2NoZW1hKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgSW5kZXhlZERCTWFuYWdlci51cGdyYWRlRGF0YWJhc2UoZGIsIG9sZFZlcnNpb24sIGRiU2NoZW1hLCB0cmFuc2FjdGlvbik7XHJcbiAgICAgICAgICAgICAgICAgICAgfSxcclxuICAgICAgICAgICAgICAgICAgICBibG9ja2VkKCkge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKGBbaWRiXS5bJHtkYlNjaGVtYS5uYW1lfV06IENvbm5lY3Rpb24gdG8gZGF0YWJhc2UgZm9yIHZlcnNpb24gdXBncmFkZSBpcyBibG9ja2VkIGR1ZSB0byBvbGRlciB2ZXJzaW9ucyBvcGVuIG9uIHRoZSBvcmlnaW5gLCBkYlNjaGVtYSk7XHJcbiAgICAgICAgICAgICAgICAgICAgfSxcclxuICAgICAgICAgICAgICAgICAgICBibG9ja2luZygpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZyhgW2lkYl0uWyR7ZGJTY2hlbWEubmFtZX1dOiBUaGlzIGNvbm5lY3Rpb24gaXMgYmxvY2tpbmcgYSB2ZXJzaW9uIHVwZ3JhZGUuLi5yZWN5Y2xpbmcgdGhpcyBjb25uZWN0aW9uYCwgZGJTY2hlbWEpO1xyXG4gICAgICAgICAgICAgICAgICAgIH0sXHJcbiAgICAgICAgICAgICAgICAgICAgdGVybWluYXRlZCgpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZyhgW2lkYl0uWyR7ZGJTY2hlbWEubmFtZX1dOiBUaGlzIGNvbm5lY3Rpb24gd2FzIGFibm9ybWFsbHkgdGVybWluYXRlZCBieSB0aGUgYnJvd3Nlci4uLnJlY3ljbGluZyB0aGlzIGNvbm5lY3Rpb25gLCBkYlNjaGVtYSk7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfSkpO1xyXG4gICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICB0aGlzLl9kYkluc3RhbmNlcy5zZXQoZGJTY2hlbWEubmFtZSwgZGIpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfSBjYXRjaCAoZSkge1xyXG4gICAgICAgICAgICBkYiA9IG5ldyBJbmRleGVkREIoZGJTY2hlbWEsIGF3YWl0IG9wZW5EQihkYlNjaGVtYS5uYW1lKSk7XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB0aGlzLl9kYkluc3RhbmNlcy5zZXQoZGJTY2hlbWEubmFtZSwgZGIpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBcclxuICAgICAgICByZXR1cm4gZGI7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyBjbG9zZURiID0gYXN5bmMgKGRiTmFtZTogc3RyaW5nKSA9PiB7XHJcbiAgICAgICAgY29uc3QgZGIgPSB0aGlzLl9kYkluc3RhbmNlcy5nZXQoZGJOYW1lKTtcclxuXHJcbiAgICAgICAgaWYgKCFkYikge1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIGRiLmRpc3Bvc2UoKTtcclxuXHJcbiAgICAgICAgdGhpcy5fZGJJbnN0YW5jZXMuZGVsZXRlKGRiTmFtZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGRlbGV0ZURiID0gYXN5bmMoZGJOYW1lOiBzdHJpbmcpID0+IHtcclxuICAgICAgICBjb25zdCBkYiA9IHRoaXMuX2RiSW5zdGFuY2VzLmdldChkYk5hbWUpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGlmICghZGIpIHtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuICAgICAgICBcclxuICAgICAgICBkYi5kaXNwb3NlKCk7XHJcblxyXG4gICAgICAgIGF3YWl0IGRlbGV0ZURCKGRiTmFtZSk7XHJcblxyXG4gICAgICAgIHRoaXMuX2RiSW5zdGFuY2VzLmRlbGV0ZShkYk5hbWUpO1xyXG4gICAgfVxyXG5cclxuXHJcbiAgICBwdWJsaWMgZGJJbmZvID0gYXN5bmMoZGJOYW1lOiBzdHJpbmcpOiBQcm9taXNlPElEYkluZm9ybWF0aW9uPiA9PiB7XHJcbiAgICAgICAgY29uc3QgZGIgPSBhd2FpdCBvcGVuREIoZGJOYW1lKTtcclxuXHJcbiAgICAgICAgbGV0IGdldFN0b3JlcyA9IChsaXN0OiBET01TdHJpbmdMaXN0KTogYW55W10gPT4ge1xyXG4gICAgICAgICAgICBsZXQgc3RvcmVzOiBvYmplY3RbXSA9IFtdO1xyXG4gICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGxpc3QubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICAgICAgICAgIGxldCBzdG9yZSA9IGRiLnRyYW5zYWN0aW9uKGxpc3RbaV0pLnN0b3JlO1xyXG4gICAgICAgICAgICAgICAgbGV0IGluZGV4ZXM6IG9iamVjdFtdID0gW107XHJcbiAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIGNvbnN0IGluZGV4TmFtZXMgPSBzdG9yZS5pbmRleE5hbWVzO1xyXG4gICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBzID0gMDsgcyA8IGluZGV4TmFtZXMubGVuZ3RoOyBzKyspIHtcclxuICAgICAgICAgICAgICAgICAgICBpbmRleGVzLnB1c2goe1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBuYW1lOiBpbmRleE5hbWVzW3NdXHJcbiAgICAgICAgICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIHN0b3Jlcy5wdXNoKHtcclxuICAgICAgICAgICAgICAgICAgICBuYW1lOiBsaXN0W2ldLFxyXG4gICAgICAgICAgICAgICAgICAgIGlzS2V5VmFsOiAhc3RvcmUua2V5UGF0aCxcclxuICAgICAgICAgICAgICAgICAgICBwcmltYXJ5S2V5OiBzdG9yZS5rZXlQYXRoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgID8geyBrZXlQYXRoOiBzdG9yZS5rZXlQYXRoIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgOiBudWxsLFxyXG4gICAgICAgICAgICAgICAgICAgIGluZGV4ZXM6IGluZGV4ZXNcclxuICAgICAgICAgICAgICAgIH0pO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICByZXR1cm4gc3RvcmVzO1xyXG4gICAgICAgIH1cclxuICAgICAgICBcclxuICAgICAgICBjb25zdCBpbmZvID0ge1xyXG4gICAgICAgICAgICB2ZXJzaW9uOiBkYi52ZXJzaW9uLFxyXG4gICAgICAgICAgICBzdG9yZXM6IGdldFN0b3JlcyhkYi5vYmplY3RTdG9yZU5hbWVzKVxyXG4gICAgICAgIH07XHJcbiAgICAgICAgXHJcbiAgICAgICAgZGIuY2xvc2UoKTtcclxuICAgICAgICBcclxuICAgICAgICBpZiAoaW5mby5zdG9yZXMubGVuZ3RoID09PSAwKSB7XHJcbiAgICAgICAgICAgIGF3YWl0IGRlbGV0ZURCKGRiTmFtZSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIGNvbnNvbGUuZGVidWcoYFtpZGJdLlske2RiTmFtZX1dOiBHZW5lcmF0ZWQgY3VycmVudCBzY2hlbWEgc3VtbWFyeWAsIGluZm8pO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHJldHVybiBpbmZvO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgZGlzcG9zZSgpIHtcclxuICAgICAgICB0aGlzLl9kYkluc3RhbmNlcy5mb3JFYWNoKChkYiwgbmFtZSkgPT4ge1xyXG4gICAgICAgICAgICBkYi5kaXNwb3NlKCk7XHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzdGF0aWMgdXBncmFkZURhdGFiYXNlKHVwZ3JhZGVEQjogSURCUERhdGFiYXNlLCBvbGRWZXJzaW9uOiBudW1iZXIsIGRiU2NoZW1hOiBJRGJTY2hlbWEsIHRyYW5zYWN0aW9uOiBJREJQVHJhbnNhY3Rpb248dW5rbm93biwgU3RvcmVOYW1lczx1bmtub3duPltdLCBcInZlcnNpb25jaGFuZ2VcIj4pIHtcclxuICAgICAgICBpZiAob2xkVmVyc2lvbiA+PSBkYlNjaGVtYS52ZXJzaW9uIHx8ICFkYlNjaGVtYS5zdG9yZXMpIHtcclxuICAgICAgICAgICAgcmV0dXJuXHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIGNvbnN0IHNjaGVtYVN0b3JlTmFtZXMgPSBnZXRTY2hlbWFFbnRpdHlOYW1lcyhkYlNjaGVtYS5zdG9yZXMpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGZvciAobGV0IHN0b3JlIG9mIHVwZ3JhZGVEQi5vYmplY3RTdG9yZU5hbWVzKSB7XHJcbiAgICAgICAgICAgIGlmICghc2NoZW1hU3RvcmVOYW1lcy5pbmNsdWRlcyhzdG9yZSkpIHtcclxuICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoYFtpZGJdLlske3VwZ3JhZGVEQi5uYW1lfV06IERyb3BwaW5nIHN0b3JlIFske3N0b3JlfV1gKTtcclxuICAgICAgICAgICAgICAgIHVwZ3JhZGVEQi5kZWxldGVPYmplY3RTdG9yZShzdG9yZSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGZvciAobGV0IHN0b3JlIG9mIGRiU2NoZW1hLnN0b3Jlcykge1xyXG4gICAgICAgICAgICBpZiAoIXVwZ3JhZGVEQi5vYmplY3RTdG9yZU5hbWVzLmNvbnRhaW5zKHN0b3JlLm5hbWUpKSB7XHJcbiAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKGBbaWRiXS5bJHt1cGdyYWRlREIubmFtZX1dOiBBZGRpbmcgc3RvcmUgWyR7c3RvcmUubmFtZX1dYCk7XHJcbiAgICAgICAgICAgICAgICBJbmRleGVkREJNYW5hZ2VyLmFkZE5ld1N0b3JlKHVwZ3JhZGVEQiwgc3RvcmUpO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgSW5kZXhlZERCTWFuYWdlci51cGdyYWRlRXhpc3RpbmdTdG9yZSh1cGdyYWRlREIsIHN0b3JlLCB0cmFuc2FjdGlvbik7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzdGF0aWMgYWRkTmV3U3RvcmUodXBncmFkZURCOiBJREJQRGF0YWJhc2UsIHN0b3JlOiBJU3RvcmVTY2hlbWEpIHtcclxuICAgICAgICBpZiAoc3RvcmUuaXNLZXlWYWwpIHtcclxuICAgICAgICAgICAgdXBncmFkZURCLmNyZWF0ZU9iamVjdFN0b3JlKHN0b3JlLm5hbWUpO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCBwcmltYXJ5S2V5ID0gc3RvcmUucHJpbWFyeUtleTtcclxuXHJcbiAgICAgICAgaWYgKCFwcmltYXJ5S2V5KSB7XHJcbiAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoYFtpZGJdLlske3VwZ3JhZGVEQi5uYW1lfV06IE5vIFBLIGRldGVjdGVkIGluIHN0b3JlIFske3N0b3JlLm5hbWV9XS4gQ3JlYXRpbmcgZGVmYXVsdCB3aXRoIGtleVBhdGggJ2lkJ2ApO1xyXG4gICAgICAgICAgICBwcmltYXJ5S2V5ID0geyBuYW1lOiAnaWQnLCBrZXlQYXRoOiAnaWQnLCBhdXRvOiB0cnVlIH07XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBuZXdTdG9yZSA9IHVwZ3JhZGVEQi5jcmVhdGVPYmplY3RTdG9yZShzdG9yZS5uYW1lLCB7IGtleVBhdGg6IHByaW1hcnlLZXkua2V5UGF0aCwgYXV0b0luY3JlbWVudDogcHJpbWFyeUtleS5hdXRvIH0pO1xyXG5cclxuICAgICAgICBmb3IgKGNvbnN0IGluZGV4IG9mIHN0b3JlLmluZGV4ZXMpIHtcclxuICAgICAgICAgICAgbmV3U3RvcmUuY3JlYXRlSW5kZXgoaW5kZXgubmFtZSwgaW5kZXgua2V5UGF0aCwgeyB1bmlxdWU6IGluZGV4LnVuaXF1ZSwgbXVsdGlFbnRyeTogaW5kZXgubXVsdGlFbnRyeSB9KTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHByaXZhdGUgc3RhdGljIHVwZ3JhZGVFeGlzdGluZ1N0b3JlKHVwZ3JhZGVEQjogSURCUERhdGFiYXNlLCBzdG9yZTogSVN0b3JlU2NoZW1hLCB0cmFuc2FjdGlvbjogSURCUFRyYW5zYWN0aW9uPHVua25vd24sIFN0b3JlTmFtZXM8dW5rbm93bj5bXSwgXCJ2ZXJzaW9uY2hhbmdlXCI+KSB7XHJcbiAgICAgICAgY29uc3QgZGJTdG9yZSA9IHRyYW5zYWN0aW9uLm9iamVjdFN0b3JlKHN0b3JlLm5hbWUpO1xyXG5cclxuICAgICAgICAvLyBpZiBjaGFuZ2UgaW4gc3RvcmUgdHlwZSByZWJ1aWxkIHN0b3JlXHJcbiAgICAgICAgaWYgKCFkYlN0b3JlLmtleVBhdGggJiYgIXN0b3JlLmlzS2V5VmFsIHx8IGRiU3RvcmUua2V5UGF0aCAmJiBkYlN0b3JlLmtleVBhdGggIT0gc3RvcmUucHJpbWFyeUtleS5rZXlQYXRoKSB7XHJcbiAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoYFtpZGJdLlske3VwZ3JhZGVEQi5uYW1lfV06IFNpZ25pZmljYW50IGNoYW5nZSBkZXRlY3RlZCBpbiBzdG9yZSBbJHtzdG9yZS5uYW1lfV0gcmVxdWlyaW5nIHJlYnVpbGRgKTtcclxuICAgICAgICAgICAgdXBncmFkZURCLmRlbGV0ZU9iamVjdFN0b3JlKHN0b3JlLm5hbWUpO1xyXG4gICAgICAgICAgICBJbmRleGVkREJNYW5hZ2VyLmFkZE5ld1N0b3JlKHVwZ3JhZGVEQiwgc3RvcmUpO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIGNvbnN0IHNjaGVtYUluZGV4TmFtZXMgPSBnZXRTY2hlbWFFbnRpdHlOYW1lcyhzdG9yZS5pbmRleGVzKTtcclxuICAgICAgICBcclxuICAgICAgICBmb3IgKGxldCBpbmRleCBvZiBkYlN0b3JlLmluZGV4TmFtZXMpIHtcclxuICAgICAgICAgICAgaWYgKCFzY2hlbWFJbmRleE5hbWVzLmluY2x1ZGVzKGluZGV4KSkge1xyXG4gICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZyhgW2lkYl0uWyR7dXBncmFkZURCLm5hbWV9XTogRHJvcHBpbmcgaW5kZXggWyR7c3RvcmUubmFtZX1dLlske2luZGV4fV1gKTtcclxuICAgICAgICAgICAgICAgIGRiU3RvcmUuZGVsZXRlSW5kZXgoaW5kZXgpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBmb3IgKGxldCBpbmRleCBvZiBzdG9yZS5pbmRleGVzKSB7XHJcbiAgICAgICAgICAgIGlmICghZGJTdG9yZS5pbmRleE5hbWVzLmNvbnRhaW5zKGluZGV4Lm5hbWUpKSB7XHJcbiAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKGBbaWRiXS5bJHt1cGdyYWRlREIubmFtZX1dOiBBZGRpbmcgaW5kZXggWyR7c3RvcmUubmFtZX1dLlske2luZGV4Lm5hbWV9XWApO1xyXG4gICAgICAgICAgICAgICAgZGJTdG9yZS5jcmVhdGVJbmRleChpbmRleC5uYW1lLCBpbmRleC5rZXlQYXRoLCB7IHVuaXF1ZTogaW5kZXgudW5pcXVlLCBtdWx0aUVudHJ5OiBpbmRleC5tdWx0aUVudHJ5IH0pO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgSW5kZXhlZERCIHtcclxuICAgIG5hbWU6IHN0cmluZztcclxuICAgIHZlcnNpb246IG51bWJlcjtcclxuXHJcbiAgICBwcml2YXRlIF9kaXNwb3NlZDogYm9vbGVhbiA9IGZhbHNlO1xyXG4gICAgcHJpdmF0ZSBfaW5zdGFuY2U6IElEQlBEYXRhYmFzZTtcclxuICAgIFxyXG4gICAgY29uc3RydWN0b3Ioc3RvcmU6IElEYlNjaGVtYSwgaW5zdGFuY2U6IElEQlBEYXRhYmFzZSkge1xyXG4gICAgICAgIHRoaXMubmFtZSA9IHN0b3JlLm5hbWU7XHJcbiAgICAgICAgdGhpcy52ZXJzaW9uID0gc3RvcmUudmVyc2lvbjtcclxuICAgICAgICBcclxuICAgICAgICB0aGlzLl9pbnN0YW5jZSA9IGluc3RhbmNlO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBjbGVhclN0b3JlID0gYXN5bmMgKHN0b3JlTmFtZTogc3RyaW5nKSA9PiB7XHJcbiAgICAgICAgYXdhaXQgdGhpcy5faW5zdGFuY2UuY2xlYXIoc3RvcmVOYW1lKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZGVsZXRlU3RvcmUgPSBhc3luYyAoc3RvcmVOYW1lOiBzdHJpbmcpID0+IHtcclxuICAgICAgICBhd2FpdCB0aGlzLl9pbnN0YW5jZS5kZWxldGVPYmplY3RTdG9yZShzdG9yZU5hbWUpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBhZGQgPSBhc3luYyAoc3RvcmVOYW1lOiBzdHJpbmcsIGRhdGE6IGFueSkgPT4ge1xyXG4gICAgICAgIGF3YWl0IHRoaXMuX2luc3RhbmNlLmFkZChzdG9yZU5hbWUsIGRhdGEpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBwdXQgPSBhc3luYyAoc3RvcmVOYW1lOiBzdHJpbmcsIGRhdGE6IGFueSwga2V5PzogYW55KSA9PiB7XHJcbiAgICAgICAgYXdhaXQgdGhpcy5faW5zdGFuY2UucHV0KHN0b3JlTmFtZSwgZGF0YSwga2V5KTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgcHV0QWxsID0gYXN5bmMgKHN0b3JlTmFtZTogc3RyaW5nLCBkYXRhOiBhbnlbXSkgPT4ge1xyXG4gICAgICAgIGNvbnN0IHR4ID0gdGhpcy5faW5zdGFuY2UudHJhbnNhY3Rpb24oc3RvcmVOYW1lLCAncmVhZHdyaXRlJyk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGRhdGEpIHtcclxuICAgICAgICAgICAgYXdhaXQgdHguc3RvcmUucHV0KGl0ZW0pO1xyXG4gICAgICAgIH1cclxuICAgICAgICBcclxuICAgICAgICBhd2FpdCB0eC5kb25lO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBkZWxldGUgPSBhc3luYyAoc3RvcmVOYW1lOiBzdHJpbmcsIGtleTogYW55KSA9PiB7XHJcbiAgICAgICAgY29uc3QgZUtleSA9IEluZGV4ZWREQi5ldmFsdWF0ZUtleShrZXkpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGlmIChBcnJheS5pc0FycmF5KGVLZXkpKSB7XHJcbiAgICAgICAgICAgIGNvbnN0IHR4ID0gdGhpcy5faW5zdGFuY2UudHJhbnNhY3Rpb24oc3RvcmVOYW1lLCAncmVhZHdyaXRlJyk7XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBmb3IgKGNvbnN0IGsgb2YgZUtleSkge1xyXG4gICAgICAgICAgICAgICAgYXdhaXQgdHguc3RvcmUuZGVsZXRlKGspO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBhd2FpdCB0eC5kb25lO1xyXG4gICAgICAgICAgICBcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuICAgICAgICBcclxuICAgICAgICBhd2FpdCB0aGlzLl9pbnN0YW5jZS5kZWxldGUoc3RvcmVOYW1lLCBlS2V5KTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0ID0gYXN5bmMgKHN0b3JlTmFtZTogc3RyaW5nLCBxdWVyeTogYW55LCBmaWx0ZXJzPzogc3RyaW5nW10pOiBQcm9taXNlPGFueT4gPT4ge1xyXG4gICAgICAgIGNvbnN0IGZpbHRlckZucyA9IEluZGV4ZWREQi5ldmFsdWF0ZUZpbHRlcnMoZmlsdGVycyk7XHJcbiAgICAgICAgY29uc3Qga2V5ID0gSW5kZXhlZERCLmV2YWx1YXRlS2V5KHF1ZXJ5KTtcclxuICAgICAgICBcclxuICAgICAgICBpZiAoa2V5ICYmICFmaWx0ZXJGbnMubGVuZ3RoKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBhd2FpdCB0aGlzLl9pbnN0YW5jZS5nZXQoc3RvcmVOYW1lLCBrZXkpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgbGV0IGN1cnNvciA9IGF3YWl0IHRoaXMuX2luc3RhbmNlLnRyYW5zYWN0aW9uKHN0b3JlTmFtZSkuc3RvcmUub3BlbkN1cnNvcihrZXkpO1xyXG5cclxuICAgICAgICB3aGlsZSAoY3Vyc29yKSB7XHJcbiAgICAgICAgICAgIGNvbnN0IHZhbHVlID0gY3Vyc29yLnZhbHVlO1xyXG5cclxuICAgICAgICAgICAgaWYgKEluZGV4ZWREQi5pc0ZpbHRlcmVkKHZhbHVlLCBmaWx0ZXJGbnMpKSB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdmFsdWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIGN1cnNvciA9IGF3YWl0IGN1cnNvci5jb250aW51ZSgpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGdldEFsbCA9IGFzeW5jIChzdG9yZU5hbWU6IHN0cmluZywgcXVlcnk/OiBhbnksIGZpbHRlcnM/OiBzdHJpbmdbXSk6IFByb21pc2U8YW55PiA9PiB7XHJcbiAgICAgICAgY29uc3QgZmlsdGVyRm5zID0gSW5kZXhlZERCLmV2YWx1YXRlRmlsdGVycyhmaWx0ZXJzKTtcclxuICAgICAgICBjb25zdCBrZXkgPSBJbmRleGVkREIuZXZhbHVhdGVLZXkocXVlcnkpO1xyXG5cclxuICAgICAgICBpZiAoIWZpbHRlckZucy5sZW5ndGggJiYgIUFycmF5LmlzQXJyYXkoa2V5KSkge1xyXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5faW5zdGFuY2UuZ2V0QWxsKHN0b3JlTmFtZSwga2V5KTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGxldCByZWNvcmRzOiBhbnlbXSA9IFtdO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGlmIChBcnJheS5pc0FycmF5KGtleSkpIHtcclxuICAgICAgICAgICAgY29uc3Qgc3RvcmUgPSBhd2FpdCB0aGlzLl9pbnN0YW5jZS50cmFuc2FjdGlvbihzdG9yZU5hbWUpLnN0b3JlO1xyXG4gICAgICAgICAgICBcclxuICAgICAgICAgICAgZm9yIChjb25zdCBrIG9mIGtleSkge1xyXG4gICAgICAgICAgICAgICAgY29uc3QgdmFsdWUgPSBhd2FpdCBzdG9yZS5nZXQoayk7XHJcbiAgICAgICAgICAgICAgICBpZiAodmFsdWUgJiYgSW5kZXhlZERCLmlzRmlsdGVyZWQodmFsdWUsIGZpbHRlckZucykpIHtcclxuICAgICAgICAgICAgICAgICAgICByZWNvcmRzLnB1c2godmFsdWUpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICByZXR1cm4gcmVjb3JkcztcclxuICAgICAgICB9XHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IGN1cnNvciA9IGF3YWl0IHRoaXMuX2luc3RhbmNlLnRyYW5zYWN0aW9uKHN0b3JlTmFtZSkuc3RvcmUub3BlbkN1cnNvcihrZXkpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHdoaWxlIChjdXJzb3IpIHtcclxuICAgICAgICAgICAgY29uc3QgdmFsdWUgPSBjdXJzb3IudmFsdWU7XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBpZiAoSW5kZXhlZERCLmlzRmlsdGVyZWQodmFsdWUsIGZpbHRlckZucykpIHtcclxuICAgICAgICAgICAgICAgIHJlY29yZHMucHVzaCh2YWx1ZSk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIGN1cnNvciA9IGF3YWl0IGN1cnNvci5jb250aW51ZSgpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHJlY29yZHM7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGdldEZyb21JbmRleCA9IGFzeW5jIChzdG9yZU5hbWU6IHN0cmluZywgaW5kZXhOYW1lOiBzdHJpbmcsIHF1ZXJ5OiBhbnksIGZpbHRlcnM/OiBzdHJpbmdbXSk6IFByb21pc2U8YW55PiA9PiB7XHJcbiAgICAgICAgY29uc3QgZmlsdGVyRm5zID0gSW5kZXhlZERCLmV2YWx1YXRlRmlsdGVycyhmaWx0ZXJzKTtcclxuICAgICAgICBjb25zdCBrZXkgPSBJbmRleGVkREIuZXZhbHVhdGVLZXkocXVlcnkpO1xyXG5cclxuICAgICAgICBpZiAoIWZpbHRlckZucy5sZW5ndGgpIHtcclxuICAgICAgICAgICAgcmV0dXJuIGF3YWl0IHRoaXMuX2luc3RhbmNlLmdldEZyb21JbmRleChzdG9yZU5hbWUsIGluZGV4TmFtZSwga2V5KTtcclxuICAgICAgICB9XHJcbiAgICAgICAgXHJcbiAgICAgICAgbGV0IGN1cnNvciA9IGF3YWl0IHRoaXMuX2luc3RhbmNlLnRyYW5zYWN0aW9uKHN0b3JlTmFtZSkuc3RvcmUuaW5kZXgoaW5kZXhOYW1lKS5vcGVuQ3Vyc29yKGtleSk7XHJcblxyXG4gICAgICAgIHdoaWxlIChjdXJzb3IpIHtcclxuICAgICAgICAgICAgY29uc3QgdmFsdWUgPSBjdXJzb3IudmFsdWU7XHJcblxyXG4gICAgICAgICAgICBpZiAoSW5kZXhlZERCLmlzRmlsdGVyZWQodmFsdWUsIGZpbHRlckZucykpIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiB2YWx1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgY3Vyc29yID0gYXdhaXQgY3Vyc29yLmNvbnRpbnVlKCk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gbnVsbDtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0QWxsRnJvbUluZGV4ID0gYXN5bmMgKHN0b3JlTmFtZTogc3RyaW5nLCBpbmRleE5hbWU6IHN0cmluZywgcXVlcnk/OiBhbnksIGZpbHRlcnM/OiBzdHJpbmdbXSk6IFByb21pc2U8YW55PiA9PiB7XHJcbiAgICAgICAgY29uc3QgZmlsdGVyRm5zID0gSW5kZXhlZERCLmV2YWx1YXRlRmlsdGVycyhmaWx0ZXJzKTtcclxuICAgICAgICBjb25zdCBrZXkgPSBJbmRleGVkREIuZXZhbHVhdGVLZXkocXVlcnkpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGlmICghZmlsdGVyRm5zLmxlbmd0aCAmJiAhQXJyYXkuaXNBcnJheShrZXkpKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBhd2FpdCB0aGlzLl9pbnN0YW5jZS5nZXRBbGxGcm9tSW5kZXgoc3RvcmVOYW1lLCBpbmRleE5hbWUsIGtleSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIGxldCByZWNvcmRzOiBhbnlbXSA9IFtdO1xyXG5cclxuICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShrZXkpKSB7XHJcbiAgICAgICAgICAgIGNvbnN0IGluZGV4ID0gYXdhaXQgdGhpcy5faW5zdGFuY2UudHJhbnNhY3Rpb24oc3RvcmVOYW1lKS5zdG9yZS5pbmRleChpbmRleE5hbWUpO1xyXG5cclxuICAgICAgICAgICAgZm9yIChjb25zdCBrIG9mIGtleSkge1xyXG4gICAgICAgICAgICAgICAgY29uc3QgdmFsdWVzID0gYXdhaXQgaW5kZXguZ2V0QWxsKGspO1xyXG4gICAgICAgICAgICAgICAgcmVjb3JkcyA9IHJlY29yZHMuY29uY2F0KHZhbHVlcy5maWx0ZXIoKHZhbHVlKSA9PiBJbmRleGVkREIuaXNGaWx0ZXJlZCh2YWx1ZSwgZmlsdGVyRm5zKSkpXHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHJldHVybiByZWNvcmRzO1xyXG4gICAgICAgIH1cclxuICAgICAgICBcclxuICAgICAgICBsZXQgY3Vyc29yID0gYXdhaXQgdGhpcy5faW5zdGFuY2UudHJhbnNhY3Rpb24oc3RvcmVOYW1lKS5zdG9yZS5pbmRleChpbmRleE5hbWUpLm9wZW5DdXJzb3Ioa2V5KTtcclxuICAgICAgICBcclxuICAgICAgICB3aGlsZSAoY3Vyc29yKSB7XHJcbiAgICAgICAgICAgIGNvbnN0IHZhbHVlID0gY3Vyc29yLnZhbHVlO1xyXG5cclxuICAgICAgICAgICAgaWYgKEluZGV4ZWREQi5pc0ZpbHRlcmVkKHZhbHVlLCBmaWx0ZXJGbnMpKSB7XHJcbiAgICAgICAgICAgICAgICByZWNvcmRzLnB1c2godmFsdWUpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBjdXJzb3IgPSBhd2FpdCBjdXJzb3IuY29udGludWUoKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiByZWNvcmRzO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICBwdWJsaWMgZGVsZXRlQWxsRnJvbUluZGV4ID0gYXN5bmMgKHN0b3JlTmFtZTogc3RyaW5nLCBpbmRleE5hbWU6IHN0cmluZywgcXVlcnk/OiBhbnksIGZpbHRlcnM/OiBzdHJpbmdbXSkgPT4ge1xyXG4gICAgICAgIGNvbnN0IGZpbHRlckZucyA9IEluZGV4ZWREQi5ldmFsdWF0ZUZpbHRlcnMoZmlsdGVycyk7XHJcbiAgICAgICAgY29uc3Qga2V5ID0gSW5kZXhlZERCLmV2YWx1YXRlS2V5KHF1ZXJ5KTtcclxuXHJcbiAgICAgICAgY29uc3QgaW5kZXggPSBhd2FpdCB0aGlzLl9pbnN0YW5jZS50cmFuc2FjdGlvbihzdG9yZU5hbWUsICdyZWFkd3JpdGUnKS5zdG9yZS5pbmRleChpbmRleE5hbWUpO1xyXG4gICAgICAgIGNvbnN0IGtleXMgPSBBcnJheS5pc0FycmF5KGtleSlcclxuICAgICAgICAgICAgPyBrZXlcclxuICAgICAgICAgICAgOiBba2V5XTtcclxuXHJcbiAgICAgICAgZm9yIChjb25zdCBrIG9mIGtleXMpIHtcclxuICAgICAgICAgICAgbGV0IGN1cnNvciA9IGF3YWl0IGluZGV4Lm9wZW5DdXJzb3Ioayk7XHJcblxyXG4gICAgICAgICAgICB3aGlsZSAoY3Vyc29yKSB7XHJcbiAgICAgICAgICAgICAgICBjb25zdCB2YWx1ZSA9IGN1cnNvci52YWx1ZTtcclxuXHJcbiAgICAgICAgICAgICAgICBpZiAoSW5kZXhlZERCLmlzRmlsdGVyZWQodmFsdWUsIGZpbHRlckZucykpIHtcclxuICAgICAgICAgICAgICAgICAgICBjdXJzb3IuZGVsZXRlKCk7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgY3Vyc29yID0gYXdhaXQgY3Vyc29yLmNvbnRpbnVlKCk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGNvdW50ID0gYXN5bmMgKHN0b3JlTmFtZTogc3RyaW5nLCBrZXk/OiBhbnkpOiBQcm9taXNlPG51bWJlcj4gPT4ge1xyXG4gICAgICAgIHJldHVybiBhd2FpdCB0aGlzLl9pbnN0YW5jZS5jb3VudChzdG9yZU5hbWUsIEluZGV4ZWREQi5ldmFsdWF0ZUtleShrZXkpKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgY291bnRGcm9tSW5kZXggPSBhc3luYyAoc3RvcmVOYW1lOiBzdHJpbmcsIGluZGV4TmFtZTogc3RyaW5nLCBrZXk/OiBhbnkpOiBQcm9taXNlPG51bWJlcj4gPT4ge1xyXG4gICAgICAgIHJldHVybiBhd2FpdCB0aGlzLl9pbnN0YW5jZS5jb3VudEZyb21JbmRleChzdG9yZU5hbWUsIGluZGV4TmFtZSwgSW5kZXhlZERCLmV2YWx1YXRlS2V5KGtleSkpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBnZXRLZXkgPSBhc3luYyAoc3RvcmVOYW1lOiBzdHJpbmcsIHF1ZXJ5OiBhbnkpOiBQcm9taXNlPGFueT4gPT4ge1xyXG4gICAgICAgIHJldHVybiBhd2FpdCB0aGlzLl9pbnN0YW5jZS5nZXRLZXkoc3RvcmVOYW1lLCBJbmRleGVkREIuZXZhbHVhdGVLZXkocXVlcnkpKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0QWxsS2V5cyA9IGFzeW5jIChzdG9yZU5hbWU6IHN0cmluZywgcXVlcnk/OiBhbnkpOiBQcm9taXNlPGFueT4gPT4ge1xyXG4gICAgICAgIHJldHVybiB0aGlzLl9pbnN0YW5jZS5nZXRBbGxLZXlzKHN0b3JlTmFtZSwgSW5kZXhlZERCLmV2YWx1YXRlS2V5KHF1ZXJ5KSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGdldEtleUZyb21JbmRleCA9IGFzeW5jIChzdG9yZU5hbWU6IHN0cmluZywgaW5kZXhOYW1lOiBzdHJpbmcsIHF1ZXJ5OiBhbnkpOiBQcm9taXNlPGFueT4gPT4ge1xyXG4gICAgICAgIHJldHVybiBhd2FpdCB0aGlzLl9pbnN0YW5jZS5nZXRLZXlGcm9tSW5kZXgoc3RvcmVOYW1lLCBpbmRleE5hbWUsIEluZGV4ZWREQi5ldmFsdWF0ZUtleShxdWVyeSkpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBnZXRBbGxLZXlzRnJvbUluZGV4ID0gYXN5bmMgKHN0b3JlTmFtZTogc3RyaW5nLCBpbmRleE5hbWU6IHN0cmluZywgcXVlcnk/OiBhbnkpOiBQcm9taXNlPGFueT4gPT4ge1xyXG4gICAgICAgIHJldHVybiB0aGlzLl9pbnN0YW5jZS5nZXRBbGxLZXlzRnJvbUluZGV4KHN0b3JlTmFtZSwgaW5kZXhOYW1lLCBJbmRleGVkREIuZXZhbHVhdGVLZXkocXVlcnkpKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZGlzcG9zZSgpIHtcclxuICAgICAgICBpZiAodGhpcy5faW5zdGFuY2UgJiYgIXRoaXMuX2Rpc3Bvc2VkKSB7XHJcbiAgICAgICAgICAgIHRoaXMuX2luc3RhbmNlLmNsb3NlKCk7XHJcbiAgICAgICAgICAgIHRoaXMuX2Rpc3Bvc2VkID0gdHJ1ZTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHB1YmxpYyByZWN5Y2xlKGluc3RhbmNlOiBJREJQRGF0YWJhc2UpIHtcclxuICAgICAgICB0aGlzLmRpc3Bvc2UoKTtcclxuICAgICAgICBcclxuICAgICAgICB0aGlzLl9pbnN0YW5jZSA9IGluc3RhbmNlO1xyXG4gICAgICAgIHRoaXMuX2Rpc3Bvc2VkID0gZmFsc2U7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHByaXZhdGUgc3RhdGljIGlzS2V5UmFuZ2Uoa2V5OiBhbnkpIDoga2V5IGlzIElLZXlSYW5nZSB7XHJcbiAgICAgICAgcmV0dXJuIHR5cGVvZihrZXkpID09PSAnb2JqZWN0JyAmJiAoJ2xvd2VyJyBpbiBrZXkgfHwgJ3VwcGVyJyBpbiBrZXkpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc3RhdGljIGlzS2V5Q29sbGVjdGlvbihrZXk6IGFueSkgOiBib29sZWFuIHtcclxuICAgICAgICByZXR1cm4gQXJyYXkuaXNBcnJheShrZXkpICYmIGtleS5sZW5ndGggPiAwICYmIHR5cGVvZihrZXlbMF0pICE9PSAnb2JqZWN0JztcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHN0YXRpYyBpc0ZpbHRlcmVkKHJlY29yZDogYW55LCBmaWx0ZXJzOiBhbnlbXSk6IGJvb2xlYW4ge1xyXG4gICAgICAgIHJldHVybiBmaWx0ZXJzLmV2ZXJ5KChmaWx0ZXIpID0+IHtcclxuICAgICAgICAgICAgLy8gY29uc29sZS5kZWJ1ZyhgZmlsdGVyaW5nIHJlY29yZGAsIGZpbHRlciwgcmVjb3JkKTtcclxuICAgICAgICAgICAgcmV0dXJuIGZpbHRlci5jYWxsKHRoaXMsIHJlY29yZCk7XHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHByaXZhdGUgc3RhdGljIGV2YWx1YXRlS2V5KGtleT86IGFueSkgOiBhbnkge1xyXG4gICAgICAgIGlmICgha2V5KSB7XHJcbiAgICAgICAgICAgIHJldHVybiBrZXk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIGlmICh0aGlzLmlzS2V5UmFuZ2Uoa2V5KSkge1xyXG4gICAgICAgICAgICBpZiAoa2V5Lmxvd2VyICYmIGtleS51cHBlcikge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIGtleS5sb3dlciA9PT0ga2V5LnVwcGVyXHJcbiAgICAgICAgICAgICAgICAgICAgPyBJREJLZXlSYW5nZS5vbmx5KGtleS5sb3dlcilcclxuICAgICAgICAgICAgICAgICAgICA6IElEQktleVJhbmdlLmJvdW5kKGtleS5sb3dlciwga2V5LnVwcGVyLCBrZXkubG93ZXJPcGVuLCBrZXkudXBwZXJPcGVuKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBcclxuICAgICAgICAgICAgcmV0dXJuIGtleS5sb3dlclxyXG4gICAgICAgICAgICAgICAgPyBJREJLZXlSYW5nZS5sb3dlckJvdW5kKGtleS5sb3dlciwga2V5Lmxvd2VyT3BlbilcclxuICAgICAgICAgICAgICAgIDogSURCS2V5UmFuZ2UudXBwZXJCb3VuZChrZXkudXBwZXIsIGtleS51cHBlck9wZW4pO1xyXG4gICAgICAgIH1cclxuICAgICAgICBcclxuICAgICAgICBpZiAodGhpcy5pc0tleUNvbGxlY3Rpb24oa2V5KSkge1xyXG4gICAgICAgICAgICByZXR1cm4ga2V5Lmxlbmd0aCA9PSAwXHJcbiAgICAgICAgICAgICAgICA/IG51bGxcclxuICAgICAgICAgICAgICAgIDoga2V5Lmxlbmd0aCA9PSAxXHJcbiAgICAgICAgICAgICAgICAgICAgPyBrZXlbMF1cclxuICAgICAgICAgICAgICAgICAgICA6IGtleTtcclxuICAgICAgICB9XHJcbiAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHR5cGVvZihrZXkpID09PSAnb2JqZWN0J1xyXG4gICAgICAgICAgICA/IG51bGxcclxuICAgICAgICAgICAgOiBrZXk7XHJcbiAgICB9XHJcbiAgICBcclxuICAgIHByaXZhdGUgc3RhdGljIGV2YWx1YXRlRmlsdGVycyhmaWx0ZXJzPzogc3RyaW5nW10pOiBhbnlbXSB7XHJcbiAgICAgICAgaWYgKCFmaWx0ZXJzIHx8ICFmaWx0ZXJzLmxlbmd0aCkge1xyXG4gICAgICAgICAgICByZXR1cm4gW107XHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIHJldHVybiBmaWx0ZXJzLm1hcCgoZmlsdGVyKSA9PiB7XHJcbiAgICAgICAgICAgIHRyeSB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gZXZhbCgnKCcgKyBmaWx0ZXIgKyAnKScpO1xyXG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7XHJcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKGBbaWRiXTogRXJyb3IgZXZhbHVhdGluZyBmaWx0ZXIgJyR7ZmlsdGVyfScgYXMgYSBmdW5jdGlvbmApXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICAgICAgfSkuZmlsdGVyKChmbikgPT4ge1xyXG4gICAgICAgICAgICByZXR1cm4gdHlwZW9mKGZuKSA9PT0gXCJmdW5jdGlvblwiO1xyXG4gICAgICAgIH0pO1xyXG4gICAgfVxyXG59IiwiLy8gVGhlIG1vZHVsZSBjYWNoZVxudmFyIF9fd2VicGFja19tb2R1bGVfY2FjaGVfXyA9IHt9O1xuXG4vLyBUaGUgcmVxdWlyZSBmdW5jdGlvblxuZnVuY3Rpb24gX193ZWJwYWNrX3JlcXVpcmVfXyhtb2R1bGVJZCkge1xuXHQvLyBDaGVjayBpZiBtb2R1bGUgaXMgaW4gY2FjaGVcblx0dmFyIGNhY2hlZE1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF07XG5cdGlmIChjYWNoZWRNb2R1bGUgIT09IHVuZGVmaW5lZCkge1xuXHRcdHJldHVybiBjYWNoZWRNb2R1bGUuZXhwb3J0cztcblx0fVxuXHQvLyBDcmVhdGUgYSBuZXcgbW9kdWxlIChhbmQgcHV0IGl0IGludG8gdGhlIGNhY2hlKVxuXHR2YXIgbW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXSA9IHtcblx0XHQvLyBubyBtb2R1bGUuaWQgbmVlZGVkXG5cdFx0Ly8gbm8gbW9kdWxlLmxvYWRlZCBuZWVkZWRcblx0XHRleHBvcnRzOiB7fVxuXHR9O1xuXG5cdC8vIEV4ZWN1dGUgdGhlIG1vZHVsZSBmdW5jdGlvblxuXHRfX3dlYnBhY2tfbW9kdWxlc19fW21vZHVsZUlkXS5jYWxsKG1vZHVsZS5leHBvcnRzLCBtb2R1bGUsIG1vZHVsZS5leHBvcnRzLCBfX3dlYnBhY2tfcmVxdWlyZV9fKTtcblxuXHQvLyBSZXR1cm4gdGhlIGV4cG9ydHMgb2YgdGhlIG1vZHVsZVxuXHRyZXR1cm4gbW9kdWxlLmV4cG9ydHM7XG59XG5cbiIsIi8vIGRlZmluZSBnZXR0ZXIgZnVuY3Rpb25zIGZvciBoYXJtb255IGV4cG9ydHNcbl9fd2VicGFja19yZXF1aXJlX18uZCA9IChleHBvcnRzLCBkZWZpbml0aW9uKSA9PiB7XG5cdGZvcih2YXIga2V5IGluIGRlZmluaXRpb24pIHtcblx0XHRpZihfX3dlYnBhY2tfcmVxdWlyZV9fLm8oZGVmaW5pdGlvbiwga2V5KSAmJiAhX193ZWJwYWNrX3JlcXVpcmVfXy5vKGV4cG9ydHMsIGtleSkpIHtcblx0XHRcdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBrZXksIHsgZW51bWVyYWJsZTogdHJ1ZSwgZ2V0OiBkZWZpbml0aW9uW2tleV0gfSk7XG5cdFx0fVxuXHR9XG59OyIsIl9fd2VicGFja19yZXF1aXJlX18ubyA9IChvYmosIHByb3ApID0+IChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwob2JqLCBwcm9wKSkiLCIvLyBkZWZpbmUgX19lc01vZHVsZSBvbiBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLnIgPSAoZXhwb3J0cykgPT4ge1xuXHRpZih0eXBlb2YgU3ltYm9sICE9PSAndW5kZWZpbmVkJyAmJiBTeW1ib2wudG9TdHJpbmdUYWcpIHtcblx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgU3ltYm9sLnRvU3RyaW5nVGFnLCB7IHZhbHVlOiAnTW9kdWxlJyB9KTtcblx0fVxuXHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgJ19fZXNNb2R1bGUnLCB7IHZhbHVlOiB0cnVlIH0pO1xufTsiLCJpbXBvcnQgeyBJbmRleGVkREJNYW5hZ2VyIH0gZnJvbSBcIi4vaW50ZXJvcENsYXNzZXNcIjtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBjcmVhdGVNYW5hZ2VyKCkge1xyXG4gICAgcmV0dXJuIG5ldyBJbmRleGVkREJNYW5hZ2VyKCk7XHJcbn0iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=