package com.satodai.googleoauthdemo.controller;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.satodai.googleoauthdemo.domain.service.OpenIdConnectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.view.UrlBasedViewResolver;

@Controller
public class LoginController {

    @Autowired
    private OpenIdConnectService openIdConnectService;

    /**
     * ログイン画面を表示
     */
    @GetMapping("login")
    public String getLogin() {
        return "login";
    }

    /**
     * OpenID Connectを使用したログイン処理
     *
     * @return ホーム画面へリダイレクト
     */
    @PostMapping("oauth2/login")
    public String postLogin() {

        AuthorizationRequest authorizationRequest = openIdConnectService.makeRequest();

        return UrlBasedViewResolver.REDIRECT_URL_PREFIX + authorizationRequest.toURI().toString();
    }

    @GetMapping(value = "oauth2/redirect", params = {"state", "code"})
    @ResponseBody
    public String getRedirect(String state, String code) {

        // ここに本来ならstate検証がある

        TokenResponse tokenResponse = openIdConnectService.doTokenReqest(code);

        // IDトークンの検証とかあるけど全部省略
        BearerAccessToken token = tokenResponse.toSuccessResponse()
                .getTokens()
                .getBearerAccessToken();
        UserInfoResponse userInfoResponse = openIdConnectService.doUserinfoRequest(token);

        return userInfoResponse
                .toSuccessResponse()
                .getUserInfo()
                .toJSONObject()
                .toJSONString();
    }
}
