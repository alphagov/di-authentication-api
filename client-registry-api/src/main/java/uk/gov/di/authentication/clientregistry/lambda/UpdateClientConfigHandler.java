package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.util.Optional;

import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_ERROR;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_RECEIVED;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class UpdateClientConfigHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final ClientConfigValidationService validationService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateClientConfigHandler.class);

    public UpdateClientConfigHandler(
            ClientService clientService,
            ClientConfigValidationService validationService,
            AuditService auditService) {
        this.clientService = clientService;
        this.validationService = validationService;
        this.auditService = auditService;
    }

    public UpdateClientConfigHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.validationService = new ClientConfigValidationService();
        this.auditService = new AuditService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            String ipAddress = IpAddressHelper.extractIpAddress(input);
                            auditService.submitAuditEvent(
                                    UPDATE_CLIENT_REQUEST_RECEIVED,
                                    context.getAwsRequestId(),
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    AuditService.UNKNOWN,
                                    ipAddress);
                            try {
                                String clientId = input.getPathParameters().get("clientId");
                                LOGGER.info("Request received with ClientId {}", clientId);

                                UpdateClientConfigRequest updateClientConfigRequest =
                                        objectMapper.readValue(
                                                input.getBody(), UpdateClientConfigRequest.class);
                                if (!clientService.isValidClient(clientId)) {
                                    auditService.submitAuditEvent(
                                            UPDATE_CLIENT_REQUEST_ERROR,
                                            context.getAwsRequestId(),
                                            AuditService.UNKNOWN,
                                            clientId,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            ipAddress);
                                    LOGGER.error("Client with ClientId {} is not valid", clientId);
                                    return generateApiGatewayProxyResponse(
                                            400,
                                            OAuth2Error.INVALID_CLIENT
                                                    .toJSONObject()
                                                    .toJSONString());
                                }
                                Optional<ErrorObject> errorResponse =
                                        validationService.validateClientUpdateConfig(
                                                updateClientConfigRequest);
                                if (errorResponse.isPresent()) {
                                    auditService.submitAuditEvent(
                                            UPDATE_CLIENT_REQUEST_ERROR,
                                            context.getAwsRequestId(),
                                            AuditService.UNKNOWN,
                                            clientId,
                                            AuditService.UNKNOWN,
                                            AuditService.UNKNOWN,
                                            ipAddress);
                                    return generateApiGatewayProxyResponse(
                                            400, errorResponse.get().toJSONObject().toJSONString());
                                }
                                ClientRegistry clientRegistry =
                                        clientService.updateClient(
                                                clientId, updateClientConfigRequest);
                                ClientRegistrationResponse clientRegistrationResponse =
                                        new ClientRegistrationResponse(
                                                clientRegistry.getClientName(),
                                                clientRegistry.getClientID(),
                                                clientRegistry.getRedirectUrls(),
                                                clientRegistry.getContacts(),
                                                clientRegistry.getScopes(),
                                                clientRegistry.getPostLogoutRedirectUrls(),
                                                clientRegistry.getServiceType());
                                LOGGER.info("Client with ClientId {} has been updated", clientId);
                                return generateApiGatewayProxyResponse(
                                        200, clientRegistrationResponse);
                            } catch (JsonProcessingException | NullPointerException e) {
                                auditService.submitAuditEvent(
                                        UPDATE_CLIENT_REQUEST_ERROR,
                                        context.getAwsRequestId(),
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        ipAddress);
                                LOGGER.error(
                                        "Request with path parameters {} is missing request parameters",
                                        input.getPathParameters());
                                return generateApiGatewayProxyResponse(
                                        400,
                                        OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
                            }
                        });
    }
}
