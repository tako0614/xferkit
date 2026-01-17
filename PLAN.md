1) xferkit：postMessage/BroadcastChannel向けの「圧縮 + 暗号化 + Transferable自動抽出」メッセージ基盤
何が便利か

Web Worker / iframe / タブ間（BroadcastChannel）で大きめデータをやり取りするとき、現場では次がバラバラに実装されがちです。

Transferable（ArrayBuffer等）の抽出と transferList 管理（ミスるとクラッシュ/コピー地獄）

圧縮（gzip/deflate/brotli 等）で通信量を減らす

暗号化（同一オリジンでも機密データを扱う場合や、拡張/iframe連携でのリスク低減）

backpressure（送り過ぎで詰まる問題）・チャンク分割・再送

既存には Comlink のような RPC 抽象化はありますが、圧縮/暗号化/transferList 自動化まで含む「統合メッセージパイプライン」は一般的には見当たりませんでした。
また post-message-stream は postMessage 上に duplex stream を作る系ですが、圧縮/暗号化/transferList自動抽出は目的外です。

APIイメージ
```typescript
import { createXfer } from "xferkit";

const channel = createXfer(worker, {
  codec: {
    compress: { algo: "brotli", level: 6 },
    encrypt: { algo: "aes-gcm", key: myKey },
  },
  transfer: { auto: true }, // ネストした ArrayBuffer 等を自動で transferList 化
});

await channel.send({ kind: "chunk", data: bigUint8Array });
channel.on("message", (msg) => { /* ... */ });

```