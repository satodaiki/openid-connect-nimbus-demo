# NimbusによるOpenID Connect実装デモ

対応している認証プロバイダは以下の通り。

* Google

## 手順

1. 起動します
2. `localhost:8080/login`へアクセスします。
3. ログインボタンを押します。
4. 自動でリダイレクトとかなんやらあって最終的にUserinfoエンドポイントから取得した情報が表示されればOK！

## 参考資料

[OpenID Connect Core 1.0 日本語訳](http://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html)