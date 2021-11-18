package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.HttpCookie;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.Mockito.mock;

public abstract class ApiGatewayHandlerIntegrationTest {
    protected static final String LOCAL_ENDPOINT_FORMAT =
            "http://localhost:45678/restapis/%s/local/_user_request_";
    protected static final String LOCAL_API_GATEWAY_ID =
            Optional.ofNullable(System.getenv().get("API_GATEWAY_ID")).orElse("");
    protected static final String API_KEY =
            Optional.ofNullable(System.getenv().get("API_KEY")).orElse("");
    protected static final String FRONTEND_API_KEY =
            Optional.ofNullable(System.getenv().get("FRONTEND_API_KEY")).orElse("");
    public static final String ROOT_RESOURCE_URL =
            Optional.ofNullable(System.getenv().get("ROOT_RESOURCE_URL"))
                    .orElse(String.format(LOCAL_ENDPOINT_FORMAT, LOCAL_API_GATEWAY_ID));
    public static final String FRONTEND_ROOT_RESOURCE_URL =
            Optional.ofNullable(System.getenv().get("ROOT_RESOURCE_URL"))
                    .orElse(
                            String.format(
                                    LOCAL_ENDPOINT_FORMAT,
                                    Optional.ofNullable(
                                                    System.getenv().get("FRONTEND_API_GATEWAY_ID"))
                                            .orElse("")));

    protected RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler;
    protected final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();
    protected final Context context = mock(Context.class);
    protected final ConfigurationService configurationService =
            new IntegrationTestConfigurationService();

    @BeforeEach
    void flushData() {
        RedisHelper.flushData();
        DynamoHelper.flushData();
    }

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body, Map<String, String> headers, Map<String, String> queryString) {
        return makeRequest(body, headers, queryString, Map.of());
    }

    protected APIGatewayProxyResponseEvent makeRequest(
            Optional<Object> body,
            Map<String, String> headers,
            Map<String, String> queryString,
            Map<String, String> pathParams) {
        APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
        request.withHeaders(headers)
                .withQueryStringParameters(queryString)
                .withPathParameters(pathParams);
        body.ifPresent(
                o -> {
                    if (o instanceof String) {
                        request.withBody((String) o);
                    } else {
                        try {
                            request.withBody(objectMapper.writeValueAsString(o));
                        } catch (JsonProcessingException e) {
                            throw new RuntimeException("Could not serialise test body", e);
                        }
                    }
                });

        return handler.handleRequest(request, context);
    }

    protected Map<String, String> constructHeaders(Optional<HttpCookie> cookie) {
        final Map<String, String> headers = new HashMap<>();
        cookie.ifPresent(c -> headers.put("Cookie", c.toString()));
        return headers;
    }

    protected HttpCookie buildSessionCookie(String sessionID, String clientSessionID) {
        return new HttpCookie("gs", sessionID + "." + clientSessionID);
    }

    public static class IntegrationTestConfigurationService extends ConfigurationService {
        @Override
        public String getRedisHost() {
            return "localhost";
        }
    }
}
