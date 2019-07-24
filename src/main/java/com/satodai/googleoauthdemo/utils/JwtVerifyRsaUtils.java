package com.satodai.googleoauthdemo.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.springframework.stereotype.Component;

import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;

/**
 * RSA暗号のユーティリティクラス
 */
@Component
public class JwtVerifyRsaUtils {

    /**
     * RSA暗号化アルゴリズムを使用した署名の作成
     *
     * @param headerJson
     * @param payloadJson
     * @return 署名付きJWSオブジェクト
     */
    public JWSObject makeSignature(String headerJson, String payloadJson, RSAPrivateKey privateKey) throws JOSEException, ParseException {

        JWSObject jwsObject = new JWSObject(
                JWSHeader.parse(headerJson),
                new Payload(payloadJson));

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(privateKey);
        jwsObject.sign(signer);

        return jwsObject;
    }

    /**
     * RSA暗号化アルゴリズムを使用した署名の作成
     *
     * @param headerJson
     * @param payloadJson
     * @return 署名付きJWT文字列
     */
    public String makeSignatureStr(String headerJson, String payloadJson, RSAPrivateKey privateKey) throws JOSEException, ParseException {
        return makeSignature(headerJson, payloadJson, privateKey).serialize();
    }

    /**
     * RSA暗号化アルゴリズムを使用して作成された署名の検証
     *
     * @param jwt
     * @param publicKey
     * @return 検証結果
     */
    public boolean validSignature(String jwt, RSAPublicKey publicKey) throws JOSEException, ParseException {
        JWSObject decodeObject = JWSObject.parse(jwt);

        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        return decodeObject.verify(verifier);
    }

    /**
     * RSAで使用する公開鍵/秘密鍵の16進数文字列変換
     *
     * @param key
     * @return 変換結果の16進数文字列
     */
    public String encodeHexString(Key key) {
        return DatatypeConverter.printHexBinary(key.getEncoded()).toLowerCase();
    }

    /**
     * 16進数文字列を公開鍵へ変換<br/>
     * 参考サイト：https://codeday.me/jp/qa/20190215/265026.html
     *
     * @param hexStr
     * @return 公開鍵
     */
    public RSAPublicKey encodePublicKey(String hexStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = DatatypeConverter.parseHexBinary(hexStr);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        return publicKey;
    }

    /**
     * 16進数文字列を秘密鍵へ変換<br/>
     * 参考サイト：https://codeday.me/jp/qa/20190215/265026.html
     *
     * @param hexStr
     * @return 秘密鍵
     */
    public RSAPrivateKey encodePrivateKey(String hexStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = DatatypeConverter.parseHexBinary(hexStr);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) kf.generatePublic(new PKCS8EncodedKeySpec(publicKeyBytes));

        return privateKey;
    }
}
