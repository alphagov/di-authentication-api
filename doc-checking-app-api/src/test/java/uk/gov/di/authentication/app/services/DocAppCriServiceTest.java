package uk.gov.di.authentication.app.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.app.exception.UnsuccesfulCredentialResponseException;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.time.temporal.ChronoUnit;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.sharedtest.exceptions.Unchecked.unchecked;

class DocAppCriServiceTest {

    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsService = mock(KmsConnectionService.class);
    private final HTTPRequest userInfoHTTPRequest = mock(HTTPRequest.class);
    private static final URI CRI_URI = URI.create("http://cri/");
    private static final URI REDIRECT_URI = URI.create("http://redirect");
    private static final ClientID CLIENT_ID = new ClientID("some-client-id");
    private static final String SIGNING_KID = "14342354354353";
    private static final String DOC_APP_SUBJECT_ID = "some-doc-app-subject-id";
    private static final URI DOC_APP_JWKS_URI =
            URI.create("http://localhost/doc-app/.well-known/jwks.json");
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private DocAppCriService docAppCriService;

    @BeforeEach
    void setUp() {
        docAppCriService = new DocAppCriService(configService, kmsService);
        when(configService.getDocAppBackendURI()).thenReturn(CRI_URI);
        when(configService.getDocAppAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
        when(configService.getAccessTokenExpiry()).thenReturn(300L);
        when(configService.getDocAppAuthorisationCallbackURI()).thenReturn(REDIRECT_URI);
        when(configService.getEnvironment()).thenReturn("test");
    }

    @Test
    void shouldConstructTokenRequest() throws JOSEException {
        signJWTWithKMS();
        when(kmsService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(new GetPublicKeyResult().withKeyId("789789789789789"));
        TokenRequest tokenRequest = docAppCriService.constructTokenRequest(AUTH_CODE.getValue());
        assertThat(tokenRequest.getEndpointURI().toString(), equalTo(CRI_URI + "token"));
        assertThat(
                tokenRequest.getClientAuthentication().getMethod().getValue(),
                equalTo("private_key_jwt"));
        assertThat(
                tokenRequest.toHTTPRequest().getQueryParameters().get("redirect_uri").get(0),
                equalTo(REDIRECT_URI.toString()));
        assertThat(
                tokenRequest.toHTTPRequest().getQueryParameters().get("grant_type").get(0),
                equalTo(GrantType.AUTHORIZATION_CODE.getValue()));
        assertThat(
                tokenRequest.toHTTPRequest().getQueryParameters().get("client_id").get(0),
                equalTo(CLIENT_ID.getValue()));
    }

    @Test
    void shouldCallDocAppUserInfoEndpoint()
            throws IOException, JOSEException, NoSuchAlgorithmException {
        var keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        var signedJwtOne = generateSignedJWT(new JWTClaimsSet.Builder().build(), keyPair);
        var signedJwtTwo = generateSignedJWT(new JWTClaimsSet.Builder().build(), keyPair);

        var userInfoHTTPResponseContent =
                format(
                        "{"
                                + " \"sub\": \"%s\","
                                + " \"https://vocab.account.gov.uk/v1/credentialJWT\": ["
                                + "     \"%s\","
                                + "     \"%s\""
                                + "]"
                                + "}",
                        DOC_APP_SUBJECT_ID, signedJwtOne.serialize(), signedJwtTwo.serialize());

        when(configService.getDocAppJwksUri()).thenReturn(DOC_APP_JWKS_URI);

        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(userInfoHTTPResponseContent);
        when(userInfoHTTPRequest.send()).thenReturn(userInfoHTTPResponse);

        var response = docAppCriService.sendCriDataRequest(userInfoHTTPRequest, DOC_APP_SUBJECT_ID);

        assertThat(response.size(), equalTo(2));
        assertTrue(response.contains(signedJwtOne.serialize()));
        assertTrue(response.contains(signedJwtTwo.serialize()));
    }

    @Test
    void shouldThrowWhenClientSessionAndUserInfoEndpointDocAppIdDoesNotMatch()
            throws IOException, JOSEException, NoSuchAlgorithmException {
        var keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        var signedJwtOne = generateSignedJWT(new JWTClaimsSet.Builder().build(), keyPair);
        var signedJwtTwo = generateSignedJWT(new JWTClaimsSet.Builder().build(), keyPair);

        var userInfoHTTPResponseContent =
                format(
                        "{"
                                + " \"sub\": \"%s\","
                                + " \"https://vocab.account.gov.uk/v1/credentialJWT\": ["
                                + "     \"%s\","
                                + "     \"%s\""
                                + "]"
                                + "}",
                        DOC_APP_SUBJECT_ID, signedJwtOne.serialize(), signedJwtTwo.serialize());

        when(configService.getDocAppJwksUri()).thenReturn(DOC_APP_JWKS_URI);

        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(userInfoHTTPResponseContent);
        when(userInfoHTTPRequest.send()).thenReturn(userInfoHTTPResponse);

        UnsuccesfulCredentialResponseException thrown =
                assertThrows(
                        UnsuccesfulCredentialResponseException.class,
                        () -> {
                            docAppCriService.sendCriDataRequest(
                                    userInfoHTTPRequest, "different-id");
                        });

        assertEquals(
                "Sub in CRI response does not match docAppSubjectId in client session",
                thrown.getMessage());
    }

    private void signJWTWithKMS() throws JOSEException {
        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(SIGNING_KID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(CLIENT_ID),
                        singletonList(new Audience(buildURI(CRI_URI.toString(), "token"))),
                        NowHelper.nowPlus(5, ChronoUnit.MINUTES),
                        null,
                        NowHelper.now(),
                        new JWTID());
        var ecdsaSigner = new ECDSASigner(ecSigningKey);
        var jwsHeader =
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecSigningKey.getKeyID()).build();
        var signedJWT = new SignedJWT(jwsHeader, claimsSet.toJWTClaimsSet());
        unchecked(signedJWT::sign).accept(ecdsaSigner);
        var signResult = new SignResult();
        byte[] idTokenSignatureDer =
                ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());
        signResult.setSignature(ByteBuffer.wrap(idTokenSignatureDer));
        signResult.setKeyId(SIGNING_KID);
        signResult.setSigningAlgorithm(JWSAlgorithm.ES256.getName());
        when(kmsService.sign(any(SignRequest.class))).thenReturn(signResult);
    }

    public static SignedJWT generateSignedJWT(JWTClaimsSet jwtClaimsSet, KeyPair keyPair)
            throws JOSEException {
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var ecdsaSigner = new ECDSASigner((ECPrivateKey) keyPair.getPrivate());
        signedJWT.sign(ecdsaSigner);
        return signedJWT;
    }
}
