package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.entity.IdentityCredentials;

import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.tableConfig;

public class DynamoIdentityService {

    private static final String IDENTITY_CREDENTIALS_TABLE = "identity-credentials";
    private final DynamoDBMapper identityCredentialsMapper;
    private final long timeToExist;
    private final AmazonDynamoDB dynamoDB;

    public DynamoIdentityService(ConfigurationService configurationService) {
        var tableName = configurationService.getEnvironment() + "-" + IDENTITY_CREDENTIALS_TABLE;

        this.timeToExist = configurationService.getAccessTokenExpiry();
        this.dynamoDB = DynamoClientHelper.createDynamoClient(configurationService);
        this.identityCredentialsMapper = new DynamoDBMapper(dynamoDB, tableConfig(tableName));

        warmUp(tableName);
    }

    public void addCoreIdentityJWT(String subjectID, String coreIdentityJWT) {
        var identityCredentials =
                new IdentityCredentials()
                        .setSubjectID(subjectID)
                        .setCoreIdentityJWT(coreIdentityJWT)
                        .setTimeToExist(timeToExist);

        identityCredentialsMapper.save(identityCredentials);
    }

    public Optional<IdentityCredentials> getIdentityCredentials(String subjectID) {
        return Optional.ofNullable(
                identityCredentialsMapper.load(IdentityCredentials.class, subjectID));
    }

    private void warmUp(String tableName) {
        dynamoDB.describeTable(tableName);
    }
}
