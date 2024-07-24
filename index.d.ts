/* tslint:disable */
/* eslint-disable */

/* auto-generated by NAPI-RS */

export interface StoreInfo {
  latestCoinId: Uint8Array
  fullPuzzleHash: Uint8Array
  innerPuzzleHash: Uint8Array
  rootHash: Uint8Array
  amount: number
}
export interface ServerCoin {
  coin: Coin
  p2PuzzleHash: Uint8Array
  memoUrls: Array<string>
}
export interface Coin {
  parentCoinInfo: Uint8Array
  puzzleHash: Uint8Array
  amount: number
}
export declare function toCoinId(coin: Coin): Uint8Array
export declare function bytesEqual(a: Uint8Array, b: Uint8Array): boolean
export class Tls {
  constructor(certPath: string, keyPath: string)
}
export class Peer {
  static connect(nodeUri: string, networkId: string, tls: Tls): Promise<Peer>
  fetchServerCoins(launcherId: Uint8Array): Promise<ServerCoinIterator>
  fetchStoreInfo(coinId: Uint8Array): Promise<StoreInfo>
}
export class ServerCoinIterator {
  next(): Promise<ServerCoin | null>
}
export class Wallet {
  static initialSync(peer: Peer, mnemonic: string, aggSigMe: Uint8Array): Promise<Wallet>
  derivationIndex(): Promise<number>
  hasPuzzleHash(puzzleHash: Uint8Array): Promise<boolean>
  createServerCoin(launcherId: Uint8Array, amount: number, fee: number, uris: Array<string>): Promise<void>
  deleteServerCoins(coins: Array<Coin>, fee: number): Promise<void>
}
