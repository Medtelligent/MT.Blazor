import {IDBPDatabase, openDB, deleteDB, IDBPTransaction, StoreNames} from 'idb';
import {
    IDbInformation,
    IDbSchema, IKeyRange,
    IStoreSchema
} from './interopInterfaces';

let getSchemaEntityNames = (list: any[]): string[] => {
    let names: string[] = [];
    for (let i = 0; i < list.length; i++) {
        names.push(list[i].name);
    }
    return names;
}

export class IndexedDBManager {
    private _dbInstances:Map<string, IndexedDB> = new Map<string, IndexedDB>();

    public openDb = async (dbSchema: IDbSchema): Promise<IndexedDB> => {
        let db;
        
        try {
            db = this._dbInstances.get(dbSchema.name);
            
            if (!db || db.version < dbSchema.version) {
                if (db) {
                    db.dispose();
                }
                
                db = new IndexedDB(dbSchema, await openDB(dbSchema.name, dbSchema.version, {
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
        } catch (e) {
            db = new IndexedDB(dbSchema, await openDB(dbSchema.name));
            
            this._dbInstances.set(dbSchema.name, db);
        }
        
        return db;
    }
    
    public closeDb = async (dbName: string) => {
        const db = this._dbInstances.get(dbName);

        if (!db) {
            return;
        }
        
        db.dispose();

        this._dbInstances.delete(dbName);
    }

    public deleteDb = async(dbName: string) => {
        const db = this._dbInstances.get(dbName);
        
        if (!db) {
            return;
        }
        
        db.dispose();

        await deleteDB(dbName);

        this._dbInstances.delete(dbName);
    }


    public dbInfo = async(dbName: string): Promise<IDbInformation> => {
        const db = await openDB(dbName);

        let getStores = (list: DOMStringList): any[] => {
            let stores: object[] = [];
            for (let i = 0; i < list.length; i++) {
                let store = db.transaction(list[i]).store;
                let indexes: object[] = [];
                
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
        }
        
        const info = {
            version: db.version,
            stores: getStores(db.objectStoreNames)
        };
        
        db.close();
        
        if (info.stores.length === 0) {
            await deleteDB(dbName);
        }
        
        console.debug(`[idb].[${dbName}]: Generated current schema summary`, info);
        
        return info;
    }
    
    public dispose() {
        this._dbInstances.forEach((db, name) => {
            db.dispose();
        });
    }

    private static upgradeDatabase(upgradeDB: IDBPDatabase, oldVersion: number, dbSchema: IDbSchema, transaction: IDBPTransaction<unknown, StoreNames<unknown>[], "versionchange">) {
        if (oldVersion >= dbSchema.version || !dbSchema.stores) {
            return
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
            } else {
                IndexedDBManager.upgradeExistingStore(upgradeDB, store, transaction);
            }
        }
    }

    private static addNewStore(upgradeDB: IDBPDatabase, store: IStoreSchema) {
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
    
    private static upgradeExistingStore(upgradeDB: IDBPDatabase, store: IStoreSchema, transaction: IDBPTransaction<unknown, StoreNames<unknown>[], "versionchange">) {
        const dbStore = transaction.objectStore(store.name);

        // if change in store type rebuild store
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

export class IndexedDB {
    name: string;
    version: number;

    private _disposed: boolean = false;
    private _instance: IDBPDatabase;
    
    constructor(store: IDbSchema, instance: IDBPDatabase) {
        this.name = store.name;
        this.version = store.version;
        
        this._instance = instance;
    }

    public clearStore = async (storeName: string) => {
        await this._instance.clear(storeName);
    }

    public deleteStore = async (storeName: string) => {
        await this._instance.deleteObjectStore(storeName);
    }

    public add = async (storeName: string, data: any) => {
        await this._instance.add(storeName, data);
    }

    public put = async (storeName: string, data: any, key?: any) => {
        await this._instance.put(storeName, data, key);
    }

    public putAll = async (storeName: string, data: any[]) => {
        const tx = this._instance.transaction(storeName, 'readwrite');
        
        for (const item of data) {
            await tx.store.put(item);
        }
        
        await tx.done;
    }

    public delete = async (storeName: string, key: any) => {
        const eKey = IndexedDB.evaluateKey(key);
        
        if (Array.isArray(eKey)) {
            const tx = this._instance.transaction(storeName, 'readwrite');
            
            for (const k of eKey) {
                await tx.store.delete(k);
            }

            await tx.done;
            
            return;
        }
        
        await this._instance.delete(storeName, eKey);
    }

    public get = async (storeName: string, query: any, filters?: string[]): Promise<any> => {
        const filterFns = IndexedDB.evaluateFilters(filters);
        const key = IndexedDB.evaluateKey(query);
        
        if (key && !filterFns.length) {
            return await this._instance.get(storeName, key);
        }

        let cursor = await this._instance.transaction(storeName).store.openCursor(key);

        while (cursor) {
            const value = cursor.value;

            if (IndexedDB.isFiltered(value, filterFns)) {
                return value;
            }

            cursor = await cursor.continue();
        }

        return null;
    }

    public getAll = async (storeName: string, query?: any, filters?: string[]): Promise<any> => {
        const filterFns = IndexedDB.evaluateFilters(filters);
        const key = IndexedDB.evaluateKey(query);

        if (!filterFns.length && !Array.isArray(key)) {
            return this._instance.getAll(storeName, key);
        }

        let records: any[] = [];
        
        if (Array.isArray(key)) {
            const store = await this._instance.transaction(storeName).store;
            
            for (const k of key) {
                const value = await store.get(k);
                if (value && IndexedDB.isFiltered(value, filterFns)) {
                    records.push(value);
                }
            }
            
            return records;
        }
        
        let cursor = await this._instance.transaction(storeName).store.openCursor(key);
        
        while (cursor) {
            const value = cursor.value;
            
            if (IndexedDB.isFiltered(value, filterFns)) {
                records.push(value);
            }

            cursor = await cursor.continue();
        }

        return records;
    }

    public getFromIndex = async (storeName: string, indexName: string, query: any, filters?: string[]): Promise<any> => {
        const filterFns = IndexedDB.evaluateFilters(filters);
        const key = IndexedDB.evaluateKey(query);

        if (!filterFns.length) {
            return await this._instance.getFromIndex(storeName, indexName, key);
        }
        
        let cursor = await this._instance.transaction(storeName).store.index(indexName).openCursor(key);

        while (cursor) {
            const value = cursor.value;

            if (IndexedDB.isFiltered(value, filterFns)) {
                return value;
            }

            cursor = await cursor.continue();
        }

        return null;
    }

    public getAllFromIndex = async (storeName: string, indexName: string, query?: any, filters?: string[]): Promise<any> => {
        const filterFns = IndexedDB.evaluateFilters(filters);
        const key = IndexedDB.evaluateKey(query);
        
        if (!filterFns.length && !Array.isArray(key)) {
            return await this._instance.getAllFromIndex(storeName, indexName, key);
        }
        
        let records: any[] = [];

        if (Array.isArray(key)) {
            const index = await this._instance.transaction(storeName).store.index(indexName);

            for (const k of key) {
                const values = await index.getAll(k);
                records = records.concat(values.filter((value) => IndexedDB.isFiltered(value, filterFns)))
            }

            return records;
        }
        
        let cursor = await this._instance.transaction(storeName).store.index(indexName).openCursor(key);
        
        while (cursor) {
            const value = cursor.value;

            if (IndexedDB.isFiltered(value, filterFns)) {
                records.push(value);
            }

            cursor = await cursor.continue();
        }

        return records;
    }
    
    public deleteAllFromIndex = async (storeName: string, indexName: string, query?: any, filters?: string[]) => {
        const filterFns = IndexedDB.evaluateFilters(filters);
        const key = IndexedDB.evaluateKey(query);

        const index = await this._instance.transaction(storeName, 'readwrite').store.index(indexName);
        const keys = Array.isArray(key)
            ? key
            : [key];

        for (const k of keys) {
            let cursor = await index.openCursor(k);

            while (cursor) {
                const value = cursor.value;

                if (IndexedDB.isFiltered(value, filterFns)) {
                    cursor.delete();
                }

                cursor = await cursor.continue();
            }
        }
    }

    public count = async (storeName: string, key?: any): Promise<number> => {
        return await this._instance.count(storeName, IndexedDB.evaluateKey(key));
    }

    public countFromIndex = async (storeName: string, indexName: string, key?: any): Promise<number> => {
        return await this._instance.countFromIndex(storeName, indexName, IndexedDB.evaluateKey(key));
    }

    public getKey = async (storeName: string, query: any): Promise<any> => {
        return await this._instance.getKey(storeName, IndexedDB.evaluateKey(query));
    }

    public getAllKeys = async (storeName: string, query?: any): Promise<any> => {
        return this._instance.getAllKeys(storeName, IndexedDB.evaluateKey(query));
    }

    public getKeyFromIndex = async (storeName: string, indexName: string, query: any): Promise<any> => {
        return await this._instance.getKeyFromIndex(storeName, indexName, IndexedDB.evaluateKey(query));
    }

    public getAllKeysFromIndex = async (storeName: string, indexName: string, query?: any): Promise<any> => {
        return this._instance.getAllKeysFromIndex(storeName, indexName, IndexedDB.evaluateKey(query));
    }

    public dispose() {
        if (this._instance && !this._disposed) {
            this._instance.close();
            this._disposed = true;
        }
    }
    
    public recycle(instance: IDBPDatabase) {
        this.dispose();
        
        this._instance = instance;
        this._disposed = false;
    }
    
    private static isKeyRange(key: any) : key is IKeyRange {
        return typeof(key) === 'object' && ('lower' in key || 'upper' in key);
    }

    private static isKeyCollection(key: any) : boolean {
        return Array.isArray(key) && key.length > 0 && typeof(key[0]) !== 'object';
    }

    private static isFiltered(record: any, filters: any[]): boolean {
        return filters.every((filter) => {
            // console.debug(`filtering record`, filter, record);
            return filter.call(this, record);
        });
    }
    
    private static evaluateKey(key?: any) : any {
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
        
        return typeof(key) === 'object'
            ? null
            : key;
    }
    
    private static evaluateFilters(filters?: string[]): any[] {
        if (!filters || !filters.length) {
            return [];
        }
        
        return filters.map((filter) => {
            try {
                return eval('(' + filter + ')');
            } catch (e) {
                console.error(`[idb]: Error evaluating filter '${filter}' as a function`)
            }
            return null;
        }).filter((fn) => {
            return typeof(fn) === "function";
        });
    }
}