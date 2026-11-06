# 実装して理解するパスキー／WebAuthn ── サンプルコード

書籍『**実装して理解するパスキー／WebAuthn ── TypeScriptで作り、Keycloakで運用する**』の公式サンプルコードリポジトリです。

---

## 📁 ディレクトリ構成

```text
.
├── ch02/                # 第2章：パスキーを自前で実装する（最小構成の登録・認証セレモニー）
├── ch04/                # 第4章：実務レベルへ引き上げる（パスワード併用・複数鍵管理・Conditional UI）
└── ch05/                # 第5章：Keycloak でパスキーを運用する（IdP による認証統合・OIDC 連携）
```

- **`ch02/`**: Hono + `@simplewebauthn/server` による最小構成のパスキー登録・認証セレモニーです。discoverable credentials（resident key）によるユーザー名なしログインとセッション管理を体験します。
- **`ch04/`**: 既存のパスワード認証との併用、同一認証器の二重登録防止（`excludeCredentials`）、複数パスキーの名前付け・一覧・削除、およびオートフィルでパスキーを提示する Conditional UI（`mediation: "conditional"`）を組み込んだ実践版です。
- **`ch05/`**: パスキーの管理を Keycloak 26.1 に任せ、Hono アプリ側は OpenID Connect（OIDC）で認証結果（ID トークン）を受け取る本番運用構成です。ローカル Keycloak 起動用の `compose.yml` も含みます。

---

## 🚀 クイックスタート

動かしたい章のディレクトリに移動し、依存パッケージのインストールと起動を行います。  
動作確認には **Google Chrome** の使用を推奨します（※macOS 上の Safari では `http://localhost` 環境における OS 自動入力メニューの仕様上、Conditional UI が発火しない場合があります）。

### 第2章を実行する場合（最小実装）:

```bash
cd ch02
npm install

# .env を作成
cp .env.example .env

npm run dev
```

起動後、Google Chrome で `http://localhost:3000` にアクセスし、「Register Passkey」→「Login with Passkey」の順に動作を確認してください。

---

### 第4章を実行する場合（実務レベル実装）:

```bash
cd ch04
npm install

# .env を作成
cp .env.example .env

npm run dev
```

起動後、Google Chrome で `http://localhost:3000` にアクセスします。
1. `alice` / `password123` で「Login with Password」をクリックしてログイン
2. 「Add Passkey」でパスキーを追加登録（二重登録ブロックも確認可能）
3. 「Logout」後、ユーザー名入力欄をクリックして Conditional UI（オートフィル）からパスキーを選択してログイン

> 💡 **注意**: 第2章で作成した `localhost` 用のパスキーが OS のパスワードマネージャーに残っていると候補が重複するため、事前に OS の「パスワード」アプリ等から既存の `localhost` パスキーを削除しておくとスムーズです。

---

### 第5章を実行する場合（Keycloak 運用）:

#### 1. Keycloak を起動する

```bash
cd ch05
docker compose up -d
```

起動後、ブラウザで `http://localhost:8080` を開き、管理コンソールにログインします。
- **ユーザー名**: `admin`
- **パスワード**: `admin`

書籍の手順に従い、Realm（`passkey-book`）、Client（`passkey-book-app`）、User（`alice`）、WebAuthn Passwordless ポリシーおよび認証フロー（`browser-passkey`）を設定してください。

#### 2. アプリケーションを起動する

```bash
# .env を作成
cp .env.example .env
# .env の OIDC_CLIENT_SECRET を Keycloak の管理画面で取得した値に編集

npm install
npm run dev
```

起動後、ブラウザで `http://localhost:3000` にアクセスし、「Login with Keycloak (OIDC)」をクリックしてください。初回は Required Action でパスキーを登録し、次回以降はパスキーによるパスワードレスログインが行えます。

---

## 🛠 技術スタック

- **Runtime**: Node.js (v20+)
- **Language**: TypeScript
- **Web Framework**: [Hono](https://hono.dev/)
- **Server Adapter**: `@hono/node-server`
- **WebAuthn Library**: [@simplewebauthn/server](https://simplewebauthn.dev/)
- **Identity Provider**: Keycloak 26.1 (Docker)

---

## 📄 ライセンス

MIT License
