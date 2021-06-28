package uk.gov.di.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.Session;
import uk.gov.di.helpers.IdGenerator;

import java.util.Map;
import java.util.Optional;

public class SessionService {

    private static final String SESSION_ID_HEADER = "Session-Id";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;

    public SessionService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
    }

    public SessionService(ConfigurationService configurationService) {
        this(
                configurationService,
                new RedisConnectionService(
                        configurationService.getRedisHost(),
                        configurationService.getRedisPort(),
                        configurationService.getUseRedisTLS(),
                        configurationService.getRedisPassword()));
    }

    public Session createSession() {
        return new Session(IdGenerator.generate());
    }

    public void save(Session session) {
        try {
            redisConnectionService.saveWithExpiry(
                    session.getSessionId(),
                    OBJECT_MAPPER.writeValueAsString(session),
                    configurationService.getSessionExpiry());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<Session> getSessionFromRequestHeaders(Map<String, String> headers) {
        if (headers == null || headers.isEmpty() || !headers.containsKey(SESSION_ID_HEADER)) {
            return Optional.empty();
        }
        try {
            String sessionId = headers.get(SESSION_ID_HEADER);
            if (redisConnectionService.keyExists(sessionId)) {
                return Optional.of(
                        OBJECT_MAPPER.readValue(
                                redisConnectionService.getValue(sessionId), Session.class));
            }
            return Optional.empty();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
