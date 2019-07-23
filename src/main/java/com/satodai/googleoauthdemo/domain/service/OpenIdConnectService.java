package com.satodai.googleoauthdemo.domain.service;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
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

    public AuthorizationRequest makeRequest() {

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
        Scope scope = new Scope("openid", "email", "profile");

        State state = new State();
        Nonce nonce = new Nonce();

        // Build the request
        AuthorizationRequest request = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), clientID)
                .scope(scope)
                .state(state)
                .redirectionURI(callback)
                .endpointURI(authzEndpoint)
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

    public UserInfoResponse doUserinfoRequest(BearerAccessToken token) {

        URI userInfoEndpoint = null;    // The UserInfoEndpoint of the OpenID provider
        try {
            userInfoEndpoint = new URI(openIdConnectGoogleProperties.getUserinfoUrl());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        BearerAccessToken bearerAccessToken = token; // The access token

        // Make the request
        UserInfoResponse userInfoResponse = null;
        try {
            userInfoResponse = UserInfoResponse.parse(new UserInfoRequest(userInfoEndpoint, token).toHTTPRequest().send());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return userInfoResponse;
    }
}
