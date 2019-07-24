package com.satodai.googleoauthdemo.utils.openid;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.satodai.googleoauthdemo.OpenIdConnectGoogleProperties;
import com.satodai.googleoauthdemo.utils.OpenIdConnectUtils;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.thymeleaf.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.interfaces.RSAPublicKey;

/**
 * Google用のOpenID Connect認証ユーティリティクラス
 *
 * @Author satodai
 */
@Component
public class OpenIdConnectGoogleUtilsImpl implements OpenIdConnectUtils {

    @Autowired
    OpenIdConnectGoogleProperties openIdConnectGoogleProperties;

    /**
     * ユーザー認証リクエスト作成
     *
     * @return ユーザー認証リクエスト
     */
    @Override
    public AuthenticationRequest makeAuthenticationRequest() {

        URI authzEndpoint = null;
        URI callback = null;
        try {
            authzEndpoint = new URI(openIdConnectGoogleProperties.getAuthorizationUrl());
            callback = new URI(openIdConnectGoogleProperties.getRedirectUrl());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        // The client identifier provisioned by the server
        ClientID clientID = new ClientID(openIdConnectGoogleProperties.getClientId());

        // スコープを設定
        String[] scopeArray = openIdConnectGoogleProperties.getScope().split(" ");
        Scope scope = new Scope(scopeArray);

        State state = new State();
        Nonce nonce = new Nonce();

        // Build the request
        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                scope,
                clientID,
                callback)
                .endpointURI(authzEndpoint)
                .state(state)
                .nonce(nonce)
                .customParameter("access_type", "offline") // リフレッシュトークン取得用フィールド
                .build();

        return request;
    }

    /**
     * Tokenエンドポイントリクエストの作成
     *
     * @param code ユーザー認証エンドポイントから発行された認可コード
     * @return Tokenエンドポイントリクエスト
     */
    @Override
    public TokenRequest makeTokenRequest(String code) {

        AuthorizationCode authorizationCode = new AuthorizationCode(code);

        URI callback = null;
        URI tokenEndpoint = null;

        try {
            callback = new URI(openIdConnectGoogleProperties.getRedirectUrl());
            tokenEndpoint = new URI(openIdConnectGoogleProperties.getTokenUrl());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authorizationCode, callback);

        // The credentials to authenticate the client at the token endpoint
        ClientID clientID = new ClientID(openIdConnectGoogleProperties.getClientId());
        Secret clientSecret = new Secret(openIdConnectGoogleProperties.getClientSecret());
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

        // Make the token request
        TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

        return request;
    }

    /**
     * Tokenエンドポイントリクエスト発行
     *
     * @param request Tokenエンドポイントリクエスト
     * @return Tokenエンドポイントからのレスポンス
     */
    @Override
    public TokenResponse doTokenReqest(TokenRequest request) {

        // リクエストの発行
        TokenResponse response = null;
        try {
            response = TokenResponse.parse(request.toHTTPRequest().send());
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return response;
    }

    /**
     * JWKSエンドポイントから公開鍵を取得
     *
     * @param kid キーID
     * @return 公開鍵
     */
    public RSAPublicKey doJwksRequest(String kid) {
        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<String> jwks = restTemplate.getForEntity(openIdConnectGoogleProperties.getJwksUrl(), String.class);

        if (HttpStatus.OK.value() != jwks.getStatusCode().value()) {
            return null;
        }

        ObjectMapper mapper = new ObjectMapper();

        JsonNode keys = null;
        try {
            keys = mapper.readTree(jwks.getBody()).get("keys");
        } catch (IOException e) {
            e.printStackTrace();
        }

        JsonNode targetKey = null;

        for (JsonNode key : keys) {
            if (StringUtils.equals(kid, key.get("kid").asText())) {
                targetKey = key;
            }
        }

        RSAPublicKey rsaPublicKey = null;

        try {
            JSONObject pubicJwkComponents = JSONObjectUtils.parse(targetKey.toString());
            RSAKey rsaKey = RSAKey.parse(pubicJwkComponents);
            rsaPublicKey = (RSAPublicKey) rsaKey.toPublicKey();
        } catch (java.text.ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        }

        return rsaPublicKey;
    }

    /**
     * Userinfoエンドポイントリクエストの作成
     *
     * @param token Tokenエンドポイントで発行されたアクセストークン
     * @return Userinfoエンドポイントリクエスト
     */
    @Override
    public UserInfoRequest makeUserInfoRequest(BearerAccessToken token) {

        URI userInfoEndpoint = null;    // The UserInfoEndpoint of the OpenID provider
        try {
            userInfoEndpoint = new URI(openIdConnectGoogleProperties.getUserinfoUrl());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        BearerAccessToken bearerAccessToken = token; // The access token

        // Make the request
        UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoEndpoint, token);

        return userInfoRequest;
    }

    /**
     * Userinfoエンドポイントリクエスト発行
     *
     * @param userInfoRequest Userinfoエンドポイントリクエスト
     * @return レスポンス
     */
    @Override
    public UserInfoResponse doUserinfoRequest(UserInfoRequest userInfoRequest) {

        UserInfoResponse userInfoResponse = null;
        try {
            userInfoResponse = UserInfoResponse.parse(userInfoRequest.toHTTPRequest().send());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return userInfoResponse;
    }

}
