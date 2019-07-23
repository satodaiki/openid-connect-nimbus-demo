package com.satodai.googleoauthdemo;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("openid-connect.google")
@Data
public class OpenIdConnectGoogleProperties {

    private String clientId;

    private String clientSecret;

    private String authorizationUrl;

    private String tokenUrl;

    private String userinfoUrl;

    private String redirectUrl;
}
