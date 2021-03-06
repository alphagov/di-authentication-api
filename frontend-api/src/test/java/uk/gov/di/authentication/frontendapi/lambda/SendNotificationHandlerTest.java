package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class SendNotificationHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "07755551084";
    private static final String TEST_SIX_DIGIT_CODE = "123456";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final long BLOCKED_EMAIL_DURATION = 799;
    private static final String CLIENT_ID = "client-id";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final ClientRegistry clientRegistry =
            new ClientRegistry().setTestClient(false).setClientID(CLIENT_ID);
    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .setTestClient(true)
                    .setClientID(TEST_CLIENT_ID)
                    .setTestClientEmailAllowlist(
                            List.of(
                                    "joe.bloggs@digital.cabinet-office.gov.uk",
                                    "jb2@digital.cabinet-office.gov.uk"));

    private final Context context = mock(Context.class);
    private static final Json objectMapper = SerializationService.getInstance();

    private final Session session =
            new Session(IdGenerator.generate()).setEmailAddress(TEST_EMAIL_ADDRESS);

    private final SendNotificationHandler handler =
            new SendNotificationHandler(
                    configurationService,
                    sessionService,
                    clientSessionService,
                    clientService,
                    authenticationService,
                    awsSqsClient,
                    codeGeneratorService,
                    codeStorageService);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(SendNotificationHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        session.getSessionId(),
                                        CLIENT_ID,
                                        TEST_CLIENT_ID,
                                        TEST_EMAIL_ADDRESS,
                                        TEST_PHONE_NUMBER))));
    }

    @BeforeEach
    void setup() {
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.getBlockedEmailDuration()).thenReturn(BLOCKED_EMAIL_DURATION);
        when(codeGeneratorService.sixDigitCode()).thenReturn(TEST_SIX_DIGIT_CODE);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getEnvironment()).thenReturn("unit-test");
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
    }

    @Test
    void shouldReturn204AndPutMessageOnQueueForAValidVerifyEmailRequest()
            throws Json.JsonException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, TEST_SIX_DIGIT_CODE);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        usingValidSession();
        usingValidClientSession(CLIENT_ID);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());

        verify(awsSqsClient).send(serialisedRequest);
        verify(codeStorageService)
                .saveOtpCode(
                        TEST_EMAIL_ADDRESS, TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, VERIFY_EMAIL);
        verify(sessionService).save(argThat(this::isSessionWithEmailSent));
    }

    @Test
    void shouldUseExistingOtpCodeIfOneExists() throws Json.JsonException {
        usingValidSession();
        usingValidClientSession(CLIENT_ID);

        when(codeStorageService.getOtpCode(any(String.class), any(NotificationType.class)))
                .thenReturn(Optional.of(TEST_SIX_DIGIT_CODE));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        var notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, TEST_SIX_DIGIT_CODE);
        verify(awsSqsClient).send(objectMapper.writeValueAsString(notifyRequest));
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        verify(codeGeneratorService, never()).sixDigitCode();
        verify(codeStorageService, never())
                .saveOtpCode(
                        any(String.class),
                        any(String.class),
                        anyLong(),
                        any(NotificationType.class));
        verify(awsSqsClient).send(serialisedRequest);
        assertThat(result, hasStatus(204));
    }

    @Test
    void shouldReturn204AndNotPutMessageOnQueueForAValidRequestUsingTestClientWithAllowedEmail()
            throws Json.JsonException {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, TEST_SIX_DIGIT_CODE);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        usingValidSession();
        usingValidClientSession(TEST_CLIENT_ID);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());

        verify(awsSqsClient, never()).send(serialisedRequest);
        verify(codeStorageService)
                .saveOtpCode(
                        TEST_EMAIL_ADDRESS, TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, VERIFY_EMAIL);
        verify(sessionService).save(argThat(this::isSessionWithEmailSent));
    }

    @Test
    void shouldReturn400IfInvalidSessionProvided() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());

        verify(awsSqsClient, never()).send(anyString());
        verify(codeStorageService, never())
                .saveOtpCode(anyString(), anyString(), anyLong(), any(NotificationType.class));
        verify(sessionService, never()).save(argThat(this::isSessionWithEmailSent));
    }

    @Test
    void shouldReturn400IfRequestIsMissingEmail() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody("{ }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn500IfMessageCannotBeSentToQueue() throws Json.JsonException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, TEST_SIX_DIGIT_CODE);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);
        Mockito.doThrow(SdkClientException.class).when(awsSqsClient).send(eq(serialisedRequest));

        usingValidSession();
        usingValidClientSession(CLIENT_ID);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(500, result.getStatusCode());
        assertTrue(result.getBody().contains("Error sending message to queue"));
    }

    @Test
    void shouldReturn400WhenInvalidNotificationType() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, "VERIFY_PASSWORD"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verify(awsSqsClient, never()).send(anyString());
        verify(codeStorageService, never())
                .saveOtpCode(anyString(), anyString(), anyLong(), any(NotificationType.class));
    }

    @Test
    void shouldReturn204AndPutMessageOnQueueForAValidVerifyPhoneNumberRequest() {
        usingValidSession();
        usingValidClientSession(CLIENT_ID);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
    }

    @Test
    void shouldReturn400WhenVerifyTypeIsVerifyPhoneNumberButRequestIsMissingNumber() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1011));
    }

    @Test
    void shouldReturn400IfUserHasReachedTheEmailCodeRequestLimit() {
        maxOutCodeRequestCount();
        usingValidSession();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1029));
        verify(codeStorageService)
                .saveBlockedForEmail(
                        TEST_EMAIL_ADDRESS,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX,
                        BLOCKED_EMAIL_DURATION);
        verify(codeStorageService, never())
                .saveOtpCode(
                        TEST_EMAIL_ADDRESS, TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, VERIFY_EMAIL);
    }

    @Test
    void shouldReturn400IfUserHasReachedThePhoneCodeRequestLimit() {
        maxOutCodeRequestCount();
        usingValidSession();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1030));
        verify(codeStorageService)
                .saveBlockedForEmail(
                        TEST_EMAIL_ADDRESS,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX,
                        BLOCKED_EMAIL_DURATION);
        verify(codeStorageService, never())
                .saveOtpCode(
                        TEST_EMAIL_ADDRESS,
                        TEST_SIX_DIGIT_CODE,
                        CODE_EXPIRY_TIME,
                        VERIFY_PHONE_NUMBER);
    }

    @Test
    void shouldReturn400IfUserIsBlockedFromRequestingAnyMoreOtpCodes() {
        when(codeStorageService.isBlockedForEmail(
                        TEST_EMAIL_ADDRESS, CODE_REQUEST_BLOCKED_KEY_PREFIX))
                .thenReturn(true);
        usingValidSession();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1031));
    }

    @Test
    void shouldReturn400IfUserIsBlockedFromEnteringEmailOtpCodes() {
        when(codeStorageService.isBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);
        usingValidSession();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1033));
    }

    @Test
    void shouldReturn400IfUserIsBlockedFromEnteringPhoneOtpCodes() {
        when(codeStorageService.isBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);
        usingValidSession();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1034));
    }

    @Test
    void shouldReturn204WhenSendingAccountCreationEmail() throws Json.JsonException {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION);
        verify(awsSqsClient).send(objectMapper.writeValueAsString(notifyRequest));

        assertEquals(204, result.getStatusCode());
    }

    @Test
    void shouldReturn204AndNotSendAccountCreationEmailForTestClientAndTestUser()
            throws Json.JsonException {
        usingValidSession();
        usingValidClientSession(TEST_CLIENT_ID);
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION);
        verify(awsSqsClient, never()).send(objectMapper.writeValueAsString(notifyRequest));

        assertEquals(204, result.getStatusCode());
    }

    private void maxOutCodeRequestCount() {
        session.incrementCodeRequestCount();
        session.incrementCodeRequestCount();
        session.incrementCodeRequestCount();
        session.incrementCodeRequestCount();
        session.incrementCodeRequestCount();
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private void usingValidClientSession(String clientId) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                scope,
                                new ClientID(clientId),
                                REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .build();
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getAuthRequestParams()).thenReturn(authRequest.toParameters());
    }

    private boolean isSessionWithEmailSent(Session session) {
        return session.getEmailAddress().equals(TEST_EMAIL_ADDRESS)
                && session.getCodeRequestCount() == 1;
    }
}
