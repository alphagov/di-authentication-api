package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.SessionHelper;
import uk.gov.di.entity.CheckUserExistsResponse;
import uk.gov.di.entity.UserWithEmailRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.entity.SessionState.AUTHENTICATION_REQUIRED;

public class UserExistsIntegrationTest extends IntegrationTestEndpoints {

    private static final String USEREXISTS_ENDPOINT = "/user-exists";
    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallUserExistsResourceAndReturn200() throws IOException {
        Client client = ClientBuilder.newClient();
        WebTarget webTarget = client.target(ROOT_RESOURCE_URL + USEREXISTS_ENDPOINT);
        String sessionId = SessionHelper.createSession();
        Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
        MultivaluedMap headers = new MultivaluedHashMap();
        headers.add("Session-Id", sessionId);

        UserWithEmailRequest request =
                new UserWithEmailRequest("joe.bloggs@digital.cabinet-office.gov.uk");

        Response response =
                invocationBuilder
                        .headers(headers)
                        .post(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertEquals(200, response.getStatus());

        String responseString = response.readEntity(String.class);
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(responseString, CheckUserExistsResponse.class);
        assertEquals(request.getEmail(), checkUserExistsResponse.getEmail());
        assertEquals(AUTHENTICATION_REQUIRED, checkUserExistsResponse.getSessionState());
    }
}
