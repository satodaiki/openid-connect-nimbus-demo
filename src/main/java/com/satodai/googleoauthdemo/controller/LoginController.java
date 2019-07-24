package com.satodai.googleoauthdemo.controller;

import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.satodai.googleoauthdemo.domain.service.OpenIdConnectService;
import com.satodai.googleoauthdemo.entity.session.OpenIdConnectSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.view.UrlBasedViewResolver;
import org.thymeleaf.util.StringUtils;

import java.util.Optional;

@Controller
public class LoginController {

    @Autowired
    private OpenIdConnectService openIdConnectService;

    /** セッション */
    @Autowired
    OpenIdConnectSession session;

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

        AuthenticationRequest authenticationRequest = openIdConnectService.makeAuthenticationRequest();

        // StateとNonceをセッションに保存
        session.setState(authenticationRequest.getState());
        session.setNonce(authenticationRequest.getNonce());

        return UrlBasedViewResolver.REDIRECT_URL_PREFIX + authenticationRequest.toURI().toString();
    }

    @GetMapping(value = "oauth2/redirect", params = {"state", "code"})
    @ResponseBody
    public String getRedirect(Optional<String> state, Optional<String> code) {

        // stateの検証
        if (!StringUtils.equals(state.get(), session.getState().getValue())) {
            return "{\"error\":\"state-dame-desu\"}";
        }

        TokenResponse tokenResponse = openIdConnectService.doTokenReqest(code.get());

        // IDトークンの検証
        boolean idTokenVerifyResult = openIdConnectService.verifyTokenResponse(tokenResponse, session.getNonce());

        if (!idTokenVerifyResult) {
            return "{\"error\":\"state-dame-desu\"}";
        }

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
