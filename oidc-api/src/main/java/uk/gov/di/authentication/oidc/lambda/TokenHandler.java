package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.AuthCodeExchangeData;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.services.AuthenticationService;
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
import java.util.Optional;

import static java.lang.String.format;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.RequestBodyHelper.parseRequestBody;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class TokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(TokenHandler.class);

    private final ClientService clientService;
    private final TokenService tokenService;
    private final AuthenticationService authenticationService;
    private final ConfigurationService configurationService;
    private final AuthorisationCodeService authorisationCodeService;
    private final ClientSessionService clientSessionService;
    private final TokenValidationService tokenValidationService;
    private final RedisConnectionService redisConnectionService;
    private static final String TOKEN_PATH = "/token";
    private static final String REFRESH_TOKEN_PREFIX = "REFRESH";

    public TokenHandler(
            ClientService clientService,
            TokenService tokenService,
            AuthenticationService authenticationService,
            ConfigurationService configurationService,
            AuthorisationCodeService authorisationCodeService,
            ClientSessionService clientSessionService,
            TokenValidationService tokenValidationService,
            RedisConnectionService redisConnectionService) {
        this.clientService = clientService;
        this.tokenService = tokenService;
        this.authenticationService = authenticationService;
        this.configurationService = configurationService;
        this.authorisationCodeService = authorisationCodeService;
        this.clientSessionService = clientSessionService;
        this.tokenValidationService = tokenValidationService;
        this.redisConnectionService = redisConnectionService;
    }

    public TokenHandler() {
        configurationService = new ConfigurationService();
        clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        tokenService =
                new TokenService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        new KmsConnectionService(configurationService));
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.authorisationCodeService = new AuthorisationCodeService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.tokenValidationService =
                new TokenValidationService(
                        configurationService, new KmsConnectionService(configurationService));
        this.redisConnectionService = new RedisConnectionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            Optional<ErrorObject> invalidRequestParamError =
                                    tokenService.validateTokenRequestParams(input.getBody());
                            if (invalidRequestParamError.isPresent()) {
                                LOG.error("Parameters missing from Token Request");
                                return generateApiGatewayProxyResponse(
                                        400,
                                        invalidRequestParamError
                                                .get()
                                                .toJSONObject()
                                                .toJSONString());
                            }

                            Map<String, String> requestBody = parseRequestBody(input.getBody());
                            String clientID = requestBody.get("client_id");
                            ClientRegistry client;
                            try {
                                client = clientService.getClient(clientID).orElseThrow();
                            } catch (NoSuchElementException e) {
                                LOG.error(
                                        "Client not found in Client Registry with Client ID {}",
                                        clientID);
                                return generateApiGatewayProxyResponse(
                                        400,
                                        OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString());
                            }
                            String baseUrl =
                                    configurationService
                                            .getBaseURL()
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
                            String tokenUrl = baseUrl + TOKEN_PATH;
                            Optional<ErrorObject> invalidPrivateKeyJwtError =
                                    tokenService.validatePrivateKeyJWT(
                                            input.getBody(), client.getPublicKey(), tokenUrl);
                            if (invalidPrivateKeyJwtError.isPresent()) {
                                LOG.error(
                                        "Private Key JWT is not valid for Client ID {}", clientID);
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
                                return processRefreshTokenRequest(
                                        requestBody,
                                        client.getScopes(),
                                        new RefreshToken(requestBody.get("refresh_token")));
                            }
                            AuthCodeExchangeData authCodeExchangeData;
                            try {
                                authCodeExchangeData =
                                        authorisationCodeService
                                                .getExchangeDataForCode(requestBody.get("code"))
                                                .orElseThrow();
                            } catch (NoSuchElementException e) {
                                LOG.error("Could not retrieve client session ID from code", e);
                                return generateApiGatewayProxyResponse(
                                        400,
                                        OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
                            }
                            ClientSession clientSession =
                                    clientSessionService.getClientSession(
                                            authCodeExchangeData.getClientSessionId());
                            AuthenticationRequest authRequest;
                            try {
                                authRequest =
                                        AuthenticationRequest.parse(
                                                clientSession.getAuthRequestParams());
                            } catch (ParseException e) {
                                LOG.error("Could not parse authentication request", e);
                                throw new RuntimeException(
                                        format(
                                                "Unable to parse Auth Request\n Auth Request Params: %s \n Exception: %s",
                                                clientSession.getAuthRequestParams(), e));
                            }
                            if (!authRequest
                                    .getRedirectionURI()
                                    .toString()
                                    .equals(requestBody.get("redirect_uri"))) {
                                LOG.error(
                                        "Redirect URI for auth request ({}) does not match redirect URI for request body ({})",
                                        authRequest.getRedirectionURI(),
                                        requestBody.get("redirect_uri"));
                                return generateApiGatewayProxyResponse(
                                        400,
                                        OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
                            }
                            Subject subject =
                                    authenticationService.getSubjectFromEmail(
                                            authCodeExchangeData.getEmail());
                            Map<String, Object> additionalTokenClaims = new HashMap<>();
                            if (authRequest.getNonce() != null) {
                                additionalTokenClaims.put("nonce", authRequest.getNonce());
                            }
                            OIDCTokenResponse tokenResponse =
                                    tokenService.generateTokenResponse(
                                            clientID,
                                            subject,
                                            authRequest.getScope().toStringList(),
                                            additionalTokenClaims);

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
                tokenValidationService.validateRefreshTokenSignature(currentRefreshToken);
        if (!refreshTokenSignatureValid) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }
        Subject subject;
        List<String> scopes;
        try {
            SignedJWT signedJwt = SignedJWT.parse(currentRefreshToken.getValue());
            subject = new Subject(signedJwt.getJWTClaimsSet().getSubject());
            scopes = (List<String>) signedJwt.getJWTClaimsSet().getClaim("scope");
        } catch (java.text.ParseException e) {
            LOG.error("Unable to parse RefreshToken", e);
            return generateApiGatewayProxyResponse(
                    400,
                    new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                            .toJSONObject()
                            .toJSONString());
        }
        if (!clientScopes.containsAll(scopes)) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_SCOPE.toJSONObject().toJSONString());
        }
        if (!scopes.contains(OIDCScopeValue.OFFLINE_ACCESS.getValue())) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_SCOPE.toJSONObject().toJSONString());
        }
        String clientId = requestBody.get("client_id");
        String redisKey = REFRESH_TOKEN_PREFIX + "." + clientId + "." + subject.getValue();
        Optional<String> refreshToken =
                Optional.ofNullable(redisConnectionService.getValue(redisKey));
        if (refreshToken.isEmpty()) {
            LOG.error("Refresh token not found with given key");
            return generateApiGatewayProxyResponse(
                    400,
                    new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                            .toJSONObject()
                            .toJSONString());
        }
        if (!new RefreshToken(refreshToken.get()).equals(currentRefreshToken)) {
            LOG.error("Refresh token found does not match Refresh token in request");
            return generateApiGatewayProxyResponse(
                    400,
                    new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                            .toJSONObject()
                            .toJSONString());
        }
        redisConnectionService.deleteValue(redisKey);
        OIDCTokenResponse tokenResponse =
                tokenService.generateRefreshTokenResponse(clientId, subject, scopes);
        return generateApiGatewayProxyResponse(200, tokenResponse.toJSONObject().toJSONString());
    }
}
