package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.amazonaws.services.s3.AmazonS3;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.service.notify.NotificationClientException;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.PASSWORD_RESET_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class NotificationHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567891";
    private static final String NOTIFY_PHONE_NUMBER = "01234567899";
    private static final String BUCKET_NAME = "test-s3-bucket";
    private static final String TEST_RESET_PASSWORD_LINK =
            "https://localhost:8080/frontend?reset-password?code=123456.54353464565";
    private static final String FRONTEND_BASE_URL = "https://localhost:8080/frontend";
    private static final String CONTACT_US_LINK_ROUTE = "contact-us";
    private final Context context = mock(Context.class);
    private final NotificationService notificationService = mock(NotificationService.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final AmazonS3 s3Client = mock(AmazonS3.class);
    private NotificationHandler handler;
    private static final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    void setUp() {
        when(configService.getNotifyTestDestinations()).thenReturn(List.of(NOTIFY_PHONE_NUMBER));
        when(configService.getSmoketestBucketName()).thenReturn(BUCKET_NAME);
        when(configService.getFrontendBaseUrl()).thenReturn(FRONTEND_BASE_URL);
        when(configService.getContactUsLinkRoute()).thenReturn(CONTACT_US_LINK_ROUTE);
        handler = new NotificationHandler(notificationService, configService, s3Client);
    }

    @Test
    void shouldSuccessfullyProcessEmailMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=confirmEmailAddressEmail";

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService).sendEmail(TEST_EMAIL_ADDRESS, personalisation, VERIFY_EMAIL);
    }

    @Test
    void shouldSuccessfullyProcessResetPasswordConfirmationFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, PASSWORD_RESET_CONFIRMATION);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=passwordResetConfirmationEmail";

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, PASSWORD_RESET_CONFIRMATION);
    }

    @Test
    void shouldSuccessfullyProcessResetPasswordEmailFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, RESET_PASSWORD, TEST_RESET_PASSWORD_LINK);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=passwordResetRequestEmail";

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("reset-password-link", TEST_RESET_PASSWORD_LINK);
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService).sendEmail(TEST_EMAIL_ADDRESS, personalisation, RESET_PASSWORD);
    }

    @Test
    void shouldSuccessfullyProcessAccountCreatedConfirmationFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        String baseUrl = "http://account-management";
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=accountCreatedEmail";
        var govUKAccountsUrl = URI.create("https://www.gov.uk/account");
        when(configService.getAccountManagementURI()).thenReturn(baseUrl);
        when(configService.getGovUKAccountsURL()).thenReturn(govUKAccountsUrl);

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);
        personalisation.put("gov-uk-accounts-url", govUKAccountsUrl.toString());

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, ACCOUNT_CREATED_CONFIRMATION);
    }

    @Test
    void shouldSuccessfullyProcessPhoneMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(notifyRequest.getDestination(), personalisation, VERIFY_PHONE_NUMBER);
    }

    @Test
    void shouldThrowExceptionIfUnableToProcessMessageFromQueue() {
        SQSEvent sqsEvent = generateSQSEvent("");

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals(
                "Error when mapping message from queue to a NotifyRequest", exception.getMessage());
    }

    @Test
    void shouldThrowExceptionIfNotifyIsUnableToSendEmail()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=confirmEmailAddressEmail";

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());
        personalisation.put("contact-us-link", contactUsLinkUrl);
        Mockito.doThrow(NotificationClientException.class)
                .when(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, VERIFY_EMAIL);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals(
                "Error sending with Notify using NotificationType: VERIFY_EMAIL",
                exception.getMessage());
    }

    @Test
    void shouldThrowExceptionIfNotifyIsUnableToSendText()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        Mockito.doThrow(NotificationClientException.class)
                .when(notificationService)
                .sendText(TEST_PHONE_NUMBER, personalisation, VERIFY_PHONE_NUMBER);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(sqsEvent, context),
                        "Expected to throw exception");

        assertEquals(
                "Error sending with Notify using NotificationType: VERIFY_PHONE_NUMBER",
                exception.getMessage());
    }

    @Test
    void shouldSuccessfullyProcessPhoneMessageFromSQSQueueAndWriteToS3WhenTestClient()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(NOTIFY_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(notifyRequest.getDestination(), personalisation, VERIFY_PHONE_NUMBER);
        verify(s3Client).putObject(BUCKET_NAME, NOTIFY_PHONE_NUMBER, "654321");
    }

    @Test
    void shouldSuccessfullyProcessMfaMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest = new NotifyRequest(TEST_PHONE_NUMBER, MFA_SMS, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(notifyRequest.getDestination(), personalisation, MFA_SMS);
    }

    @Test
    void shouldSuccessfullyProcessMfaMessageFromSQSQueueAndWriteToS3WhenTestClient()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest = new NotifyRequest(NOTIFY_PHONE_NUMBER, MFA_SMS, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(notifyRequest.getDestination(), personalisation, MFA_SMS);
        verify(s3Client).putObject(BUCKET_NAME, NOTIFY_PHONE_NUMBER, "654321");
    }

    @Test
    void shouldSuccessfullyProcessPasswordResetWithCodeMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, RESET_PASSWORD_WITH_CODE, "654321");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);
        var contactUsLinkUrl =
                "https://localhost:8080/frontend/contact-us?referer=passwordResetRequestEmail";

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, RESET_PASSWORD_WITH_CODE);
    }

    private SQSEvent generateSQSEvent(String messageBody) {
        SQSMessage sqsMessage = new SQSMessage();
        sqsMessage.setBody(messageBody);
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(singletonList(sqsMessage));
        return sqsEvent;
    }
}
