package com.satodai.googleoauthdemo.utils;

import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;

/**
 * OpenID Connectに関連する処理のユーティリティインターフェース
 */
public interface OpenIdConnectUtils {

    /**
     * ユーザー認証リクエスト作成
     *
     * @return ユーザー認証リクエスト
     */
    public AuthenticationRequest makeAuthenticationRequest();


    /**
     * Tokenエンドポイントリクエストの作成
     *
     * @param code ユーザー認証エンドポイントから発行された認可コード
     * @return Tokenエンドポイントリクエスト
     */
    public TokenRequest makeTokenRequest(String code);


    /**
     * Tokenエンドポイントリクエストの発行
     *
     * @param request Tokenエンドポイントリクエスト
     * @return Tokenエンドポイントからのレスポンス
     */
    public TokenResponse doTokenReqest(TokenRequest request);



    /**
     * Userinfoエンドポイントリクエストの作成
     *
     * @param token Tokenエンドポイントで発行されたアクセストークン
     * @return Userinfoエンドポイントリクエスト
     */
    public UserInfoRequest makeUserInfoRequest(BearerAccessToken token);

    /**
     * Userinfoエンドポイントリクエストの発行
     *
     * @param userInfoRequest Userinfoエンドポイントリクエスト
     * @return レスポンス
     */
    public UserInfoResponse doUserinfoRequest(UserInfoRequest userInfoRequest);

}
