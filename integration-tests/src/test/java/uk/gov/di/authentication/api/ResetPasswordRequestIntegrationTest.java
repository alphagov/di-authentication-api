package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordRequestHandler;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasLength;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class ResetPasswordRequestIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @BeforeEach
    public void setUp() {
        handler = new ResetPasswordRequestHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    public void shouldCallResetPasswordEndpointAndReturn200() throws Json.JsonException {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addPhoneNumber(email, phoneNumber);
        String sessionId = redis.createSession();
        String persistentSessionId = "test-persistent-id";
        redis.addEmailToSession(sessionId, email);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(email, false)),
                        constructFrontendHeaders(sessionId, null, persistentSessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(email));
        assertThat(requests.get(0).getNotificationType(), equalTo(RESET_PASSWORD));
        assertTrue(
                requests.get(0).getCode().startsWith("http://localhost:3000/reset-password?code="));

        String[] resetLinkSplit = requests.get(0).getCode().split("\\.");

        assertThat(resetLinkSplit.length, equalTo(4));
        assertThat(resetLinkSplit[2], equalTo(sessionId));
        assertThat(resetLinkSplit[3], equalTo(persistentSessionId));
    }

    @Test
    public void shouldCallResetPasswordEndpointAndReturn200ForCodeFlowRequest()
            throws Json.JsonException {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addPhoneNumber(email, phoneNumber);
        String sessionId = redis.createSession();
        String persistentSessionId = "test-persistent-id";
        redis.addEmailToSession(sessionId, email);

        var response =
                makeRequest(
                        Optional.of(new ResetPasswordRequest(email, true)),
                        constructFrontendHeaders(sessionId, null, persistentSessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        List<NotifyRequest> requests = notificationsQueue.getMessages(NotifyRequest.class);

        assertThat(requests, hasSize(1));
        assertThat(requests.get(0).getDestination(), equalTo(email));
        assertThat(requests.get(0).getNotificationType(), equalTo(RESET_PASSWORD_WITH_CODE));
        assertThat(requests.get(0).getCode(), hasLength(6));
    }
}
