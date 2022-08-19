export interface IDbSchema {
    name: string;
    version: number;
    stores: IStoreSchema[];
}

export interface IStoreSchema {
    dbVersion?: number;
    name: string;
    isKeyVal: boolean;
    primaryKey: IStoreIndexSpec;
    indexes: IStoreIndexSpec[];
}

export interface IStoreIndexSpec {
    name: string;
    keyPath: string;
    unique?: boolean;
    multiEntry?: boolean;
    auto: boolean;
}

export interface IKeyRange {
    lower: string | number | Date | null | undefined;
    lowerOpen: boolean;
    upper: string | number | Date | null | undefined;
    upperOpen: boolean;
}

export interface IDbInformation {
    version: number;
    stores: IStoreSchema[];
}