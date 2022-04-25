package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.state.UserContext;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DocAppUserHelperTest {

    private static final ClientID CLIENT_ID = new ClientID("client-id");
    private static final String CLIENT_NAME = "test-client";
    private static final Session SESSION = new Session("a-session-id");
    private static final String AUDIENCE = "oidc-audience";
    private static final String VALID_SCOPE = "openid doc-checking-app";
    private static final State STATE = new State();
    private static final String REDIRECT_URI = "https://localhost:8080";

    private static Stream<ClientType> clientTypes() {
        return Stream.of(ClientType.WEB, ClientType.APP);
    }

    @ParameterizedTest
    @MethodSource("clientTypes")
    void shouldReturnFalseIfAuthRequestDoesNotContainRequestObject(ClientType clientType) {
        var userContext = buildUserContext(clientType, null);

        assertFalse(DocAppUserHelper.isDocCheckingAppUser(userContext));
    }

    @ParameterizedTest
    @MethodSource("clientTypes")
    void shouldReturnFalseIfRequestObjectDoesNotContainDocAppScope(ClientType clientType)
            throws NoSuchAlgorithmException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);
        var userContext = buildUserContext(clientType, signedJWT);

        assertFalse(DocAppUserHelper.isDocCheckingAppUser(userContext));
    }

    @Test
    void shouldReturnFalseIfClientIsNotAppClient() throws NoSuchAlgorithmException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", VALID_SCOPE)
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);
        var userContext = buildUserContext(ClientType.WEB, signedJWT);

        assertFalse(DocAppUserHelper.isDocCheckingAppUser(userContext));
    }

    @Test
    void shouldReturnTrueIfClientIsDocCheckingAppUser()
            throws NoSuchAlgorithmException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", VALID_SCOPE)
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);
        var userContext = buildUserContext(ClientType.APP, signedJWT);

        assertTrue(DocAppUserHelper.isDocCheckingAppUser(userContext));
    }

    private UserContext buildUserContext(ClientType clientType, SignedJWT requestObject) {
        var authRequestBuilder =
                new AuthorizationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE), CLIENT_ID);
        if (Objects.nonNull(requestObject)) {
            authRequestBuilder.requestObject(requestObject);
        }
        var clientSession =
                new ClientSession(
                        authRequestBuilder.build().toParameters(),
                        LocalDateTime.now(),
                        VectorOfTrust.getDefaults());
        var clientRegistry =
                new ClientRegistry()
                        .setClientID(CLIENT_ID.getValue())
                        .setClientName(CLIENT_NAME)
                        .setConsentRequired(false)
                        .setCookieConsentShared(false)
                        .setClientType(clientType.getValue());
        return UserContext.builder(SESSION)
                .withClientSession(clientSession)
                .withClient(clientRegistry)
                .build();
    }

    private SignedJWT generateSignedJWT(JWTClaimsSet jwtClaimsSet)
            throws NoSuchAlgorithmException, JOSEException {
        var keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
    }
}