package com.satodai.googleoauthdemo.domain.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.satodai.googleoauthdemo.utils.JwtVerifyRsaUtils;
import com.satodai.googleoauthdemo.utils.openid.OpenIdConnectGoogleUtilsImpl;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.thymeleaf.util.StringUtils;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

@Service
public class OpenIdConnectService {

    @Autowired
    OpenIdConnectGoogleUtilsImpl openIdConnectUtils;

    @Autowired
    JwtVerifyRsaUtils jwtVerifyRsaUtils;

    /**
     * ユーザー認証リクエスト作成
     *
     * @return
     */
    public AuthenticationRequest makeAuthenticationRequest() {
        return openIdConnectUtils.makeAuthenticationRequest();
    }

    /**
     * トークン取得リクエスト発行
     *
     * @param code 認可コード
     * @return
     */
    public TokenResponse doTokenReqest(String code) {
        TokenRequest tokenRequest = openIdConnectUtils.makeTokenRequest(code);
        return openIdConnectUtils.doTokenReqest(tokenRequest);
    }

    /**
     * Tokenエンドポイントからのレスポンスを検証
     *
     * @param tokenResponse Tokenエンドポイントからのレスポンス
     * @return 検証結果
     */
    public boolean verifyTokenResponse(TokenResponse tokenResponse, Nonce nonce) {

        String idToken = tokenResponse.toSuccessResponse().getCustomParameters().get("id_token").toString();

        JWSObject jws = null;
        try {
            jws = JWSObject.parse(idToken);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        RSAPublicKey publicKey = openIdConnectUtils.doJwksRequest(jws.getHeader().getKeyID());

        boolean result = false;
        try {
            result = jwtVerifyRsaUtils.validSignature(jws.serialize(), publicKey);
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }

        // Nonceの検証
        JSONObject payload = jws.getPayload().toJSONObject();

        if (StringUtils.equals(nonce.getValue(), payload.getAsString("nonce"))) {
            result = true;
        }

        return result;
    }

    /**
     * ユーザー情報の取得リクエスト発行
     *
     * @param token アクセストークン
     * @return
     */
    public UserInfoResponse doUserinfoRequest(BearerAccessToken token) {
        UserInfoRequest userInfoRequest = openIdConnectUtils.makeUserInfoRequest(token);
        return openIdConnectUtils.doUserinfoRequest(userInfoRequest);
    }
}
