package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.AuthCodeExchangeData;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.LegacyRefreshTokenStore;
import uk.gov.di.authentication.shared.entity.RefreshTokenStore;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;

import static java.lang.String.format;
import static uk.gov.di.authentication.shared.conditions.DocAppUserHelper.getRequestObjectClaim;
import static uk.gov.di.authentication.shared.conditions.DocAppUserHelper.isDocCheckingAppUserWithSubjectId;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.updateAttachedLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.RequestBodyHelper.parseRequestBody;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class TokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(TokenHandler.class);

    private final ClientService clientService;
    private final TokenService tokenService;
    private final DynamoService dynamoService;
    private final ConfigurationService configurationService;
    private final AuthorisationCodeService authorisationCodeService;
    private final ClientSessionService clientSessionService;
    private final TokenValidationService tokenValidationService;
    private final RedisConnectionService redisConnectionService;
    private final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    private static final String TOKEN_PATH = "token";
    private static final String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN:";

    public TokenHandler(
            ClientService clientService,
            TokenService tokenService,
            DynamoService dynamoService,
            ConfigurationService configurationService,
            AuthorisationCodeService authorisationCodeService,
            ClientSessionService clientSessionService,
            TokenValidationService tokenValidationService,
            RedisConnectionService redisConnectionService) {
        this.clientService = clientService;
        this.tokenService = tokenService;
        this.dynamoService = dynamoService;
        this.configurationService = configurationService;
        this.authorisationCodeService = authorisationCodeService;
        this.clientSessionService = clientSessionService;
        this.tokenValidationService = tokenValidationService;
        this.redisConnectionService = redisConnectionService;
    }

    public TokenHandler(ConfigurationService configurationService) {
        var kms = new KmsConnectionService(configurationService);

        this.configurationService = configurationService;
        this.redisConnectionService = new RedisConnectionService(configurationService);

        this.clientService = new DynamoClientService(configurationService);
        this.tokenService =
                new TokenService(configurationService, this.redisConnectionService, kms);
        this.dynamoService = new DynamoService(configurationService);
        this.authorisationCodeService =
                new AuthorisationCodeService(
                        configurationService,
                        redisConnectionService,
                        ObjectMapperFactory.getInstance());
        this.clientSessionService =
                new ClientSessionService(configurationService, redisConnectionService);
        this.tokenValidationService = new TokenValidationService(configurationService, kms);
    }

    public TokenHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Token request received");
                            Optional<ErrorObject> invalidRequestParamError =
                                    tokenService.validateTokenRequestParams(input.getBody());
                            if (invalidRequestParamError.isPresent()) {
                                LOG.warn(
                                        "Invalid Token Request. ErrorCode: {}. ErrorDescription: {}",
                                        invalidRequestParamError.get().getCode(),
                                        invalidRequestParamError.get().getDescription());
                                return generateApiGatewayProxyResponse(
                                        400,
                                        invalidRequestParamError
                                                .get()
                                                .toJSONObject()
                                                .toJSONString());
                            }

                            Map<String, String> requestBody = parseRequestBody(input.getBody());
                            String clientID = requestBody.get("client_id");
                            attachLogFieldToLogs(CLIENT_ID, clientID);
                            ClientRegistry client;
                            try {
                                client = clientService.getClient(clientID).orElseThrow();
                            } catch (NoSuchElementException e) {
                                LOG.warn("Client not found in Client Registry");
                                return generateApiGatewayProxyResponse(
                                        400,
                                        OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString());
                            }
                            String baseUrl =
                                    configurationService
                                            .getOidcApiBaseURL()
                                            .orElseThrow(
                                                    () -> {
                                                        LOG.error(
                                                                "Application was not configured with baseURL");
                                                        // TODO - We need to come up with a strategy
                                                        // to handle uncaught
                                                        // exceptions
                                                        return new RuntimeException(
                                                                "Application was not configured with baseURL");
                                                    });
                            String tokenUrl = buildURI(baseUrl, TOKEN_PATH).toString();
                            Optional<ErrorObject> invalidPrivateKeyJwtError =
                                    segmentedFunctionCall(
                                            "validatePrivateKeyJWT",
                                            () ->
                                                    tokenService.validatePrivateKeyJWT(
                                                            input.getBody(),
                                                            client.getPublicKey(),
                                                            tokenUrl,
                                                            clientID));
                            if (invalidPrivateKeyJwtError.isPresent()) {
                                LOG.warn(
                                        "Private Key JWT is not valid for Client ID: {}", clientID);
                                return generateApiGatewayProxyResponse(
                                        400,
                                        invalidPrivateKeyJwtError
                                                .get()
                                                .toJSONObject()
                                                .toJSONString());
                            }

                            if (requestBody
                                    .get("grant_type")
                                    .equals(GrantType.REFRESH_TOKEN.getValue())) {
                                LOG.info("Processing refresh token request");
                                return segmentedFunctionCall(
                                        "processRefreshTokenRequest",
                                        () ->
                                                processRefreshTokenRequest(
                                                        requestBody,
                                                        client.getScopes(),
                                                        new RefreshToken(
                                                                requestBody.get("refresh_token"))));
                            }
                            AuthCodeExchangeData authCodeExchangeData;
                            try {
                                authCodeExchangeData =
                                        segmentedFunctionCall(
                                                "authorisationCodeService",
                                                () ->
                                                        authorisationCodeService
                                                                .getExchangeDataForCode(
                                                                        requestBody.get("code"))
                                                                .orElseThrow());
                            } catch (NoSuchElementException e) {
                                LOG.warn("Could not retrieve client session ID from code", e);
                                return generateApiGatewayProxyResponse(
                                        400,
                                        OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
                            }
                            updateAttachedLogFieldToLogs(
                                    CLIENT_SESSION_ID, authCodeExchangeData.getClientSessionId());
                            ClientSession clientSession = authCodeExchangeData.getClientSession();
                            AuthenticationRequest authRequest;
                            try {
                                authRequest =
                                        AuthenticationRequest.parse(
                                                clientSession.getAuthRequestParams());
                            } catch (ParseException e) {
                                LOG.warn(
                                        "Could not parse authentication request from client session",
                                        e);
                                throw new RuntimeException(
                                        format(
                                                "Unable to parse Auth Request\n Auth Request Params: %s \n Exception: %s",
                                                clientSession.getAuthRequestParams(), e));
                            }
                            if (!authRequest
                                    .getRedirectionURI()
                                    .toString()
                                    .equals(requestBody.get("redirect_uri"))) {
                                LOG.warn(
                                        "Redirect URI for auth request ({}) does not match redirect URI for request body ({})",
                                        authRequest.getRedirectionURI(),
                                        requestBody.get("redirect_uri"));
                                return generateApiGatewayProxyResponse(
                                        400,
                                        OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
                            }

                            Map<String, Object> additionalTokenClaims = new HashMap<>();
                            if (authRequest.getNonce() != null) {
                                additionalTokenClaims.put("nonce", authRequest.getNonce());
                            }
                            String vot =
                                    clientSession
                                            .getEffectiveVectorOfTrust()
                                            .retrieveVectorOfTrustForToken();

                            OIDCClaimsRequest claimsRequest = null;
                            if (Objects.nonNull(
                                            clientSession
                                                    .getEffectiveVectorOfTrust()
                                                    .getLevelOfConfidence())
                                    && Objects.nonNull(authRequest.getOIDCClaims())) {
                                claimsRequest = authRequest.getOIDCClaims();
                            }
                            var isConsentRequired =
                                    client.isConsentRequired()
                                            && !clientSession
                                                    .getEffectiveVectorOfTrust()
                                                    .containsLevelOfConfidence();
                            final OIDCClaimsRequest finalClaimsRequest = claimsRequest;
                            OIDCTokenResponse tokenResponse;
                            if (isDocCheckingAppUserWithSubjectId(clientSession)) {
                                Scope scope =
                                        new Scope(
                                                getRequestObjectClaim(
                                                        authRequest, "scope", String.class));
                                tokenResponse =
                                        segmentedFunctionCall(
                                                "generateTokenResponse",
                                                () ->
                                                        tokenService.generateTokenResponse(
                                                                clientID,
                                                                clientSession.getDocAppSubjectId(),
                                                                scope,
                                                                additionalTokenClaims,
                                                                clientSession.getDocAppSubjectId(),
                                                                vot,
                                                                null,
                                                                false,
                                                                finalClaimsRequest,
                                                                true));
                            } else {
                                UserProfile userProfile =
                                        dynamoService.getUserProfileByEmail(
                                                authCodeExchangeData.getEmail());
                                Subject publicSubject =
                                        ClientSubjectHelper.getSubject(
                                                userProfile, client, dynamoService);
                                tokenResponse =
                                        segmentedFunctionCall(
                                                "generateTokenResponse",
                                                () ->
                                                        tokenService.generateTokenResponse(
                                                                clientID,
                                                                new Subject(
                                                                        userProfile.getSubjectID()),
                                                                authRequest.getScope(),
                                                                additionalTokenClaims,
                                                                publicSubject,
                                                                vot,
                                                                userProfile.getClientConsent(),
                                                                isConsentRequired,
                                                                finalClaimsRequest,
                                                                false));
                            }

                            clientSessionService.saveClientSession(
                                    authCodeExchangeData.getClientSessionId(),
                                    clientSession.setIdTokenHint(
                                            tokenResponse
                                                    .getOIDCTokens()
                                                    .getIDToken()
                                                    .serialize()));
                            LOG.info("Successfully generated tokens");
                            return generateApiGatewayProxyResponse(
                                    200, tokenResponse.toJSONObject().toJSONString());
                        });
    }

    private APIGatewayProxyResponseEvent processRefreshTokenRequest(
            Map<String, String> requestBody,
            List<String> clientScopes,
            RefreshToken currentRefreshToken) {
        boolean refreshTokenSignatureValid =
                tokenValidationService.validateRefreshTokenSignatureAndExpiry(currentRefreshToken);
        if (!refreshTokenSignatureValid) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }
        Subject publicSubject;
        List<String> scopes;
        String jti;
        try {
            SignedJWT signedJwt = SignedJWT.parse(currentRefreshToken.getValue());
            publicSubject = new Subject(signedJwt.getJWTClaimsSet().getSubject());
            scopes = (List<String>) signedJwt.getJWTClaimsSet().getClaim("scope");
            jti = signedJwt.getJWTClaimsSet().getJWTID();
        } catch (java.text.ParseException e) {
            LOG.warn("Unable to parse RefreshToken");
            return generateApiGatewayProxyResponse(
                    400,
                    new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                            .toJSONObject()
                            .toJSONString());
        }
        boolean areScopesValid =
                tokenValidationService.validateRefreshTokenScopes(clientScopes, scopes);
        if (!areScopesValid) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_SCOPE.toJSONObject().toJSONString());
        }
        String clientId = requestBody.get("client_id");

        segmentedFunctionCall(
                "migrateRefreshTokens", () -> migrateRefreshTokens(clientId, publicSubject));
        String redisKey = REFRESH_TOKEN_PREFIX + jti;
        Optional<String> refreshToken =
                Optional.ofNullable(redisConnectionService.popValue(redisKey));
        RefreshTokenStore tokenStore;
        try {
            tokenStore = objectMapper.readValue(refreshToken.get(), RefreshTokenStore.class);
        } catch (JsonProcessingException | NoSuchElementException | IllegalArgumentException e) {
            LOG.warn("Refresh token not found with given key");
            return generateApiGatewayProxyResponse(
                    400,
                    new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                            .toJSONObject()
                            .toJSONString());
        }
        if (!tokenStore.getRefreshToken().equals(currentRefreshToken.getValue())) {
            LOG.warn("Refresh token store does not contain Refresh token in request");
            return generateApiGatewayProxyResponse(
                    400,
                    new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                            .toJSONObject()
                            .toJSONString());
        }

        OIDCTokenResponse tokenResponse =
                tokenService.generateRefreshTokenResponse(
                        clientId,
                        new Subject(tokenStore.getInternalSubjectId()),
                        scopes,
                        publicSubject);
        LOG.info("Generating successful RefreshToken response");
        return generateApiGatewayProxyResponse(200, tokenResponse.toJSONObject().toJSONString());
    }

    private boolean migrateRefreshTokens(String clientId, Subject publicSubject) {
        var existingRefreshTokens =
                Optional.ofNullable(
                        redisConnectionService.popValue(
                                REFRESH_TOKEN_PREFIX + clientId + "." + publicSubject.getValue()));

        if (existingRefreshTokens.isEmpty()) {
            return false;
        }

        LegacyRefreshTokenStore legacyRefreshTokenStore;
        try {
            legacyRefreshTokenStore =
                    objectMapper.readValue(
                            existingRefreshTokens.get(), LegacyRefreshTokenStore.class);
        } catch (JsonProcessingException e) {
            LOG.warn("Could not parse legacy refresh token store");
            return false;
        }

        legacyRefreshTokenStore
                .getRefreshTokens()
                .forEach(
                        s -> {
                            try {
                                var parsedToken = SignedJWT.parse(s);
                                redisConnectionService.saveWithExpiry(
                                        REFRESH_TOKEN_PREFIX
                                                + parsedToken.getJWTClaimsSet().getJWTID(),
                                        objectMapper.writeValueAsString(
                                                new RefreshTokenStore(
                                                        s,
                                                        legacyRefreshTokenStore
                                                                .getInternalSubjectId())),
                                        configurationService.getSessionExpiry());
                            } catch (java.text.ParseException | JsonProcessingException e) {
                                LOG.warn("Failed to migrate existing refresh token");
                            }
                        });
        return true;
    }
}
