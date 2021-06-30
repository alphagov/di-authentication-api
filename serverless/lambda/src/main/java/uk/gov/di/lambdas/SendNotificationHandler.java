package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.NotifyRequest;
import uk.gov.di.entity.SendNotificationRequest;
import uk.gov.di.entity.Session;
import uk.gov.di.services.AwsSqsClient;
import uk.gov.di.services.CodeGeneratorService;
import uk.gov.di.services.CodeStorageService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.RedisConnectionService;
import uk.gov.di.services.SessionService;
import uk.gov.di.services.ValidationService;

import java.util.Optional;

import static uk.gov.di.entity.SessionState.VERIFY_EMAIL_CODE_SENT;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class SendNotificationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;
    private final ValidationService validationService;
    private final AwsSqsClient sqsClient;
    private final SessionService sessionService;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SendNotificationHandler(
            ConfigurationService configurationService,
            ValidationService validationService,
            AwsSqsClient sqsClient,
            SessionService sessionService,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService) {
        this.configurationService = configurationService;
        this.validationService = validationService;
        this.sqsClient = sqsClient;
        this.sessionService = sessionService;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
    }

    public SendNotificationHandler() {
        this.configurationService = new ConfigurationService();
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.validationService = new ValidationService();
        sessionService = new SessionService(configurationService);
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LambdaLogger logger = context.getLogger();

        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        try {
            SendNotificationRequest sendNotificationRequest =
                    objectMapper.readValue(input.getBody(), SendNotificationRequest.class);
            switch (sendNotificationRequest.getNotificationType()) {
                case VERIFY_EMAIL:
                    Optional<ErrorResponse> emailErrorResponse =
                            validationService.validateEmailAddress(
                                    sendNotificationRequest.getEmail());
                    if (!emailErrorResponse.isEmpty()) {
                        return generateApiGatewayProxyErrorResponse(400, emailErrorResponse.get());
                    }
                    if (!session.get().validateSession(sendNotificationRequest.getEmail())) {
                        return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
                    }
                    String code = codeGeneratorService.sixDigitCode();

                    NotifyRequest notifyRequest =
                            new NotifyRequest(
                                    sendNotificationRequest.getEmail(),
                                    sendNotificationRequest.getNotificationType(),
                                    code);
                    codeStorageService.saveEmailCode(
                            sendNotificationRequest.getEmail(),
                            code,
                            configurationService.getEmailCodeExpiry());
                    sessionService.save(session.get().setState(VERIFY_EMAIL_CODE_SENT));
                    sqsClient.send(serialiseRequest(notifyRequest));
                    return generateApiGatewayProxyResponse(200, "OK");
            }
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1002);
        } catch (SdkClientException ex) {
            logger.log("Error sending message to queue: " + ex.getMessage());
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        } catch (JsonProcessingException e) {
            logger.log("Error parsing request: " + e.getMessage());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private String serialiseRequest(Object request) throws JsonProcessingException {
        return objectMapper.writeValueAsString(request);
    }
}
