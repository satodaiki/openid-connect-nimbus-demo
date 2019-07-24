package com.satodai.googleoauthdemo.domain.service;

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@Service
public class OpenIdConnectService {

    @Autowired
    OpenIdConnectGoogleProperties openIdConnectGoogleProperties;

    public AuthenticationRequest makeRequest() {

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

        // The requested scope values for the token
        Scope scope = new Scope("openid", "email", "profile", "https://www.googleapis.com/auth/calendar.events");

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
                .build();

        return request;
    }

    /**
     * トークン取得リクエスト発行
     *
     * @param code 認可コード
     * @return
     */
    public TokenResponse doTokenReqest(String code) {

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
     * ユーザー情報の取得リクエスト発行
     *
     * @param token アクセストークン
     * @return
     */
    public UserInfoResponse doUserinfoRequest(BearerAccessToken token) {

        URI userInfoEndpoint = null;    // The UserInfoEndpoint of the OpenID provider
        try {
            userInfoEndpoint = new URI(openIdConnectGoogleProperties.getUserinfoUrl());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        BearerAccessToken bearerAccessToken = token; // The access token

        // Make the request
        UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoEndpoint, token);

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
