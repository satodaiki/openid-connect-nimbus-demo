package com.satodai.googleoauthdemo.utils.openid;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.satodai.googleoauthdemo.OpenIdConnectGoogleProperties;
import net.minidev.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.StringWriter;
import java.util.Arrays;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;

@RunWith(SpringRunner.class)
@SpringBootTest
public class OpenIdConnectGoogleUtilsTest {

    @Autowired
    private OpenIdConnectGoogleProperties properties;

    @SpyBean
    private OpenIdConnectGoogleUtilsImpl openIdConnectGoogleUtilsImpl;

    @Test
    public void ユーザー認証リクエスト作成結果の正常系() throws Exception {

        AuthenticationRequest authenticationRequest = openIdConnectGoogleUtilsImpl.makeAuthenticationRequest();

        // リクエストに含まれる値を検証
        authenticationRequest.getScope().toStringList().forEach(
                scope -> assertTrue(Arrays.asList(properties.getScope().split(" ")).contains(scope))
        );
        assertEquals(properties.getClientId(), authenticationRequest.getClientID().getValue());
        assertEquals(properties.getAuthorizationUrl(), authenticationRequest.getEndpointURI().toString());
    }

    @Test
    public void Tokenエンドポイントリクエスト作成結果の正常系() throws Exception {

        // テスト用認可コード
        String code = "test";

        TokenRequest tokenRequest = openIdConnectGoogleUtilsImpl.makeTokenRequest(code);

        // リクエストに含まれる値を検証
        assertEquals(code, tokenRequest.getAuthorizationGrant().toParameters().get("code").get(0));
        assertEquals(properties.getTokenUrl(), tokenRequest.getEndpointURI().toString());
        assertEquals(properties.getClientId(), tokenRequest.getClientAuthentication().getClientID().getValue());
        // ClientSecretはリフレクション使っても容易に確認できなさそうなので確認対象外
        // assertEquals(properties.getClientSecret(), tokenRequest);
        assertEquals("authorization_code", tokenRequest.getAuthorizationGrant().toParameters().get("grant_type").get(0));
    }

    @Test
    public void Tokenエンドポイントからのレスポンス正常系() throws Exception {

        StringWriter stringWriter = new StringWriter();
        JsonGenerator jsonGenerator = new JsonFactory().createGenerator(stringWriter);

        jsonGenerator.writeStartObject();
        // ==========正常レスポンスの場合は以下のような値を出力する==========
        jsonGenerator.writeStringField("access_token", "accessToken");
        jsonGenerator.writeStringField("id_token", "idToken");
        jsonGenerator.writeNumberField("expires_in", 1234567890);
        jsonGenerator.writeStringField("token_type", "Bearer");
        jsonGenerator.writeStringField("refresh_token", "refreshToken");
        // ============================================================
        jsonGenerator.writeEndObject();

        jsonGenerator.flush();

        JSONObject jsonObject = JSONObjectUtils.parse(stringWriter.toString());

        TokenResponse tokenResponse = TokenResponse.parse(jsonObject);

        doReturn(tokenResponse).when(openIdConnectGoogleUtilsImpl).doTokenReqest(any());

        TokenResponse testRes = openIdConnectGoogleUtilsImpl.doTokenReqest(any());

        // レスポンスの検証
        assertNotNull(testRes.toSuccessResponse());

        assertEquals("accessToken", testRes.toSuccessResponse().toJSONObject().get("access_token").toString());
        assertEquals("idToken", testRes.toSuccessResponse().toJSONObject().get("id_token").toString());
        assertTrue(1234567890 == Integer.valueOf(testRes.toSuccessResponse().toJSONObject().get("expires_in").toString()));
        assertEquals("Bearer", testRes.toSuccessResponse().toJSONObject().get("token_type").toString());
        assertEquals("refreshToken", testRes.toSuccessResponse().toJSONObject().get("refresh_token").toString());
    }

    @Test
    public void Userinfoエンドポイントリクエスト作成の正常系() throws Exception {

        BearerAccessToken bearerAccessToken = new BearerAccessToken();

        UserInfoRequest userInfoRequest = openIdConnectGoogleUtilsImpl.makeUserInfoRequest(bearerAccessToken);

        // リクエストに含まれる値を検証
        assertEquals(properties.getUserinfoUrl(), userInfoRequest.getEndpointURI().toString());
        assertEquals(userInfoRequest.getAccessToken().getValue(), bearerAccessToken.getValue());
    }

    /**
     * レスポンスボディに含まれるJSONは以下のとおりです。
     *
     * {<br/>
     *   "iss": "accounts.google.com",<br/>
     *   "at_hash": "HK6E_P6Dh8Y93mRNtsDB1Q",<br/>
     *   "email_verified": "true",<br/>
     *   "sub": "10769150350006150715113082367",<br/>
     *   "azp": "1234987819200.apps.googleusercontent.com",<br/>
     *   "email": "jsmith@example.com",<br/>
     *   "aud": "1234987819200.apps.googleusercontent.com",<br/>
     *   "iat": 1353601026,<br/>
     *   "exp": 1353604926,<br/>
     *   "nonce": "0394852-3190485-2490358",<br/>
     *   "hd": "example.com"<br/>
     * }<br/>
     *
     * @throws Exception
     */
    @Test
    public void Userinfoエンドポイントからのレスポンス正常系() throws Exception {

        StringWriter stringWriter = new StringWriter();
        JsonGenerator jsonGenerator = new JsonFactory().createGenerator(stringWriter);

        jsonGenerator.writeStartObject();
        // ==========正常レスポンスの場合は以下のような値を出力する==========
        // jsonGenerator.writeStringField("access_token", "accessToken");
        // ============================================================
        jsonGenerator.writeEndObject();

        jsonGenerator.flush();

        HTTPResponse httpResponse = new HTTPResponse(HttpStatus.OK.value());
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setContent(stringWriter.toString());

        UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

        doReturn(userInfoResponse).when(openIdConnectGoogleUtilsImpl).doUserinfoRequest(any());

        UserInfoResponse testRes = openIdConnectGoogleUtilsImpl.doUserinfoRequest(any());

        // レスポンスの値を検証
    }

}
