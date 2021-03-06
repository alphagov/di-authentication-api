package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBQueryExpression;
import com.amazonaws.services.dynamodbv2.datamodeling.QueryResultPage;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.Delete;
import com.amazonaws.services.dynamodbv2.model.Put;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItem;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsRequest;
import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.dynamodb.DynamoDBSchemaHelper;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Objects.nonNull;
import static uk.gov.di.authentication.shared.dynamodb.DynamoDBSchemaHelper.Table.USER_CREDENTIALS_TABLE;
import static uk.gov.di.authentication.shared.dynamodb.DynamoDBSchemaHelper.Table.USER_PROFILE_TABLE;

public class DynamoService implements AuthenticationService {

    private final DynamoDBMapper userCredentialsMapper;
    private final DynamoDBMapper userProfileMapper;
    private final AmazonDynamoDB dynamoDB;
    private final DynamoDBSchemaHelper dynamoDBSchemaHelper;

    public DynamoService(ConfigurationService configurationService) {
        this.dynamoDB = DynamoClientHelper.createDynamoClient(configurationService);
        this.dynamoDBSchemaHelper =
                new DynamoDBSchemaHelper(dynamoDB, configurationService.getEnvironment());
        this.userCredentialsMapper =
                dynamoDBSchemaHelper.buildConfiguredDynamoDBMapper(USER_CREDENTIALS_TABLE);
        this.userProfileMapper =
                dynamoDBSchemaHelper.buildConfiguredDynamoDBMapper(USER_PROFILE_TABLE);
        warmUp(dynamoDBSchemaHelper.getFullyQualifiedTableName(USER_PROFILE_TABLE));
    }

    @Override
    public boolean userExists(String email) {
        return userProfileMapper.load(UserProfile.class, email.toLowerCase(Locale.ROOT)) != null;
    }

    @Override
    public void signUp(
            String email, String password, Subject subject, TermsAndConditions termsAndConditions) {
        String dateTime = LocalDateTime.now().toString();
        String hashedPassword = hashPassword(password);
        UserCredentials userCredentials =
                new UserCredentials()
                        .setEmail(email.toLowerCase(Locale.ROOT))
                        .setSubjectID(subject.toString())
                        .setPassword(hashedPassword)
                        .setCreated(dateTime)
                        .setUpdated(dateTime);

        UserProfile userProfile =
                new UserProfile()
                        .setEmail(email.toLowerCase(Locale.ROOT))
                        .setSubjectID(subject.toString())
                        .setEmailVerified(true)
                        .setCreated(dateTime)
                        .setUpdated(dateTime)
                        .setPublicSubjectID((new Subject()).toString())
                        .setTermsAndConditions(termsAndConditions)
                        .setLegacySubjectID(null);
        userCredentialsMapper.save(userCredentials);
        userProfileMapper.save(userProfile);
    }

    @Override
    public boolean login(String email, String password) {
        UserCredentials userCredentials =
                userCredentialsMapper.load(UserCredentials.class, email.toLowerCase(Locale.ROOT));
        return login(userCredentials, password);
    }

    @Override
    public boolean login(UserCredentials credentials, String password) {
        return Argon2MatcherHelper.matchRawStringWithEncoded(password, credentials.getPassword());
    }

    @Override
    public Subject getSubjectFromEmail(String email) {
        return new Subject(
                userProfileMapper
                        .load(UserProfile.class, email.toLowerCase(Locale.ROOT))
                        .getSubjectID());
    }

    @Override
    public void updatePhoneNumber(String email, String phoneNumber) {
        final String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(phoneNumber);
        userProfileMapper.save(
                userProfileMapper
                        .load(UserProfile.class, email.toLowerCase(Locale.ROOT))
                        .setPhoneNumber(formattedPhoneNumber));
    }

    @Override
    public void updateConsent(String email, ClientConsent clientConsent) {
        userProfileMapper.save(
                userProfileMapper
                        .load(UserProfile.class, email.toLowerCase(Locale.ROOT))
                        .setClientConsent(clientConsent));
    }

    @Override
    public UserProfile getUserProfileByEmail(String email) {
        return userProfileMapper.load(UserProfile.class, email.toLowerCase(Locale.ROOT));
    }

    @Override
    public Optional<UserProfile> getUserProfileByEmailMaybe(String email) {
        return Optional.ofNullable(getUserProfileByEmail(email));
    }

    @Override
    public void updateTermsAndConditions(String email, String version) {
        TermsAndConditions termsAndConditions =
                new TermsAndConditions(version, LocalDateTime.now(ZoneId.of("UTC")).toString());

        userProfileMapper.save(
                userProfileMapper
                        .load(UserProfile.class, email.toLowerCase(Locale.ROOT))
                        .setTermsAndConditions(termsAndConditions));
    }

    @Override
    public void updateEmail(String currentEmail, String newEmail) {
        updateEmail(currentEmail, newEmail, LocalDateTime.now(ZoneId.of("UTC")));
    }

    @Override
    public void updateEmail(String currentEmail, String newEmail, LocalDateTime updatedDateTime) {
        UserProfile userProfile =
                userProfileMapper
                        .load(UserProfile.class, currentEmail)
                        .setEmail(newEmail.toLowerCase(Locale.ROOT))
                        .setUpdated(updatedDateTime.toString());
        UserCredentials userCredentials =
                userCredentialsMapper
                        .load(UserCredentials.class, currentEmail)
                        .setEmail(newEmail.toLowerCase(Locale.ROOT))
                        .setUpdated(updatedDateTime.toString());

        Put userProfilePut = dynamoDBSchemaHelper.buildPut(USER_PROFILE_TABLE, userProfile);
        Put userCredentialsPut =
                dynamoDBSchemaHelper.buildPut(USER_CREDENTIALS_TABLE, userCredentials);
        Delete userProfileDelete =
                dynamoDBSchemaHelper.buildDelete(
                        USER_PROFILE_TABLE,
                        new AttributeValue(currentEmail.toLowerCase(Locale.ROOT)));
        Delete userCredentialsDelete =
                dynamoDBSchemaHelper.buildDelete(
                        USER_CREDENTIALS_TABLE,
                        new AttributeValue(currentEmail.toLowerCase(Locale.ROOT)));

        dynamoDB.transactWriteItems(
                new TransactWriteItemsRequest()
                        .withTransactItems(
                                Arrays.asList(
                                        new TransactWriteItem().withPut(userProfilePut),
                                        new TransactWriteItem().withPut(userCredentialsPut),
                                        new TransactWriteItem().withDelete(userProfileDelete),
                                        new TransactWriteItem()
                                                .withDelete(userCredentialsDelete))));
    }

    @Override
    public void updatePassword(String email, String newPassword) {
        userCredentialsMapper.save(
                userCredentialsMapper
                        .load(UserCredentials.class, email.toLowerCase(Locale.ROOT))
                        .setPassword(hashPassword(newPassword))
                        .setMigratedPassword(null));
    }

    @Override
    public void removeAccount(String email) {
        Delete userProfileDelete =
                dynamoDBSchemaHelper.buildDelete(
                        USER_PROFILE_TABLE, new AttributeValue(email.toLowerCase(Locale.ROOT)));
        Delete userCredentialsDelete =
                dynamoDBSchemaHelper.buildDelete(
                        USER_CREDENTIALS_TABLE, new AttributeValue(email.toLowerCase(Locale.ROOT)));
        dynamoDB.transactWriteItems(
                new TransactWriteItemsRequest()
                        .withTransactItems(
                                List.of(
                                        new TransactWriteItem().withDelete(userProfileDelete),
                                        new TransactWriteItem()
                                                .withDelete(userCredentialsDelete))));
    }

    @Override
    public UserCredentials getUserCredentialsFromSubject(String subject) {
        Map<String, AttributeValue> eav = new HashMap<>();
        eav.put(":val1", new AttributeValue().withS(subject));

        DynamoDBQueryExpression<UserCredentials> queryExpression =
                new DynamoDBQueryExpression<UserCredentials>()
                        .withIndexName("SubjectIDIndex")
                        .withKeyConditionExpression("SubjectID= :val1")
                        .withExpressionAttributeValues(eav)
                        .withConsistentRead(false);

        return getUserCredentials(queryExpression);
    }

    @Override
    public Optional<UserProfile> getUserProfileFromEmail(String email) {
        if (nonNull(email) && !email.isBlank()) {
            UserCredentials userCredentials =
                    userCredentialsMapper.load(
                            UserCredentials.class, email.toLowerCase(Locale.ROOT));

            if (nonNull(userCredentials)) {
                return Optional.of(getUserProfileFromSubject(userCredentials.getSubjectID()));
            }
        }
        return Optional.empty();
    }

    @Override
    public UserCredentials getUserCredentialsFromEmail(String email) {
        return userCredentialsMapper.load(UserCredentials.class, email.toLowerCase(Locale.ROOT));
    }

    @Override
    public void migrateLegacyPassword(String email, String password) {
        userCredentialsMapper.save(
                userCredentialsMapper
                        .load(UserCredentials.class, email.toLowerCase(Locale.ROOT))
                        .setPassword(hashPassword(password))
                        .setMigratedPassword(null));
    }

    @Override
    public void bulkAdd(
            List<UserCredentials> userCredentialsList, List<UserProfile> userProfileList) {
        userCredentialsMapper.batchSave(userCredentialsList);
        userProfileMapper.batchSave(userProfileList);
    }

    @Override
    public byte[] getOrGenerateSalt(UserProfile userProfile) {
        if (userProfile.getSalt() == null || userProfile.getSalt().array().length == 0) {
            byte[] salt = SaltHelper.generateNewSalt();
            userProfile.setSalt(salt);
            userProfileMapper.save(
                    getUserProfileFromSubject(userProfile.getSubjectID())
                            .setSalt(userProfile.getSalt()));
        }
        return userProfile.getSalt().array();
    }

    @Override
    public Optional<List<ClientConsent>> getUserConsents(String email) {
        return Optional.ofNullable(
                userProfileMapper
                        .load(UserProfile.class, email.toLowerCase(Locale.ROOT))
                        .getClientConsent());
    }

    @Override
    public void updatePhoneNumberVerifiedStatus(String email, boolean verifiedStatus) {
        userProfileMapper.save(
                userProfileMapper
                        .load(UserProfile.class, email.toLowerCase(Locale.ROOT))
                        .setPhoneNumberVerified(verifiedStatus));
    }

    @Override
    public Optional<String> getPhoneNumber(String email) {
        return Optional.ofNullable(
                userProfileMapper
                        .load(UserProfile.class, email.toLowerCase(Locale.ROOT))
                        .getPhoneNumber());
    }

    @Override
    public void updateMFAMethod(
            String email,
            MFAMethodType mfaMethodType,
            boolean methodVerified,
            boolean enabled,
            String credentialValue) {
        String dateTime = NowHelper.toTimestampString(NowHelper.now());
        MFAMethod mfaMethod =
                new MFAMethod(
                        MFAMethodType.AUTH_APP.getValue(),
                        credentialValue,
                        methodVerified,
                        enabled,
                        dateTime);
        userCredentialsMapper.save(
                userCredentialsMapper
                        .load(UserCredentials.class, email.toLowerCase(Locale.ROOT))
                        .setMfaMethod(mfaMethod));
    }

    @Override
    public void setMFAMethodVerifiedTrue(String email, MFAMethodType mfaMethodType) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());
        var userCredentials =
                userCredentialsMapper.load(UserCredentials.class, email.toLowerCase(Locale.ROOT));
        var mfaMethod =
                userCredentials.getMfaMethods().stream()
                        .filter(
                                method ->
                                        method.getMfaMethodType().equals(mfaMethodType.getValue()))
                        .findFirst()
                        .orElseThrow();

        mfaMethod.setMethodVerified(true);
        mfaMethod.setUpdated(dateTime);
        userCredentialsMapper.save(userCredentials);
    }

    @Override
    public UserProfile getUserProfileFromSubject(String subject) {
        Map<String, AttributeValue> eav = new HashMap<>();
        eav.put(":val1", new AttributeValue().withS(subject));

        DynamoDBQueryExpression<UserProfile> queryExpression =
                new DynamoDBQueryExpression<UserProfile>()
                        .withIndexName("SubjectIDIndex")
                        .withKeyConditionExpression("SubjectID= :val1")
                        .withExpressionAttributeValues(eav)
                        .withConsistentRead(false);

        return getUserProfile(queryExpression);
    }

    @Override
    public UserProfile getUserProfileFromPublicSubject(String subject) {
        Map<String, AttributeValue> eav = new HashMap<>();
        eav.put(":val1", new AttributeValue().withS(subject));

        DynamoDBQueryExpression<UserProfile> queryExpression =
                new DynamoDBQueryExpression<UserProfile>()
                        .withIndexName("PublicSubjectIDIndex")
                        .withKeyConditionExpression("PublicSubjectID= :val1")
                        .withExpressionAttributeValues(eav)
                        .withConsistentRead(false);

        return getUserProfile(queryExpression);
    }

    private UserProfile getUserProfile(DynamoDBQueryExpression<UserProfile> queryExpression) {
        QueryResultPage<UserProfile> scanPage =
                userProfileMapper.queryPage(UserProfile.class, queryExpression);
        if (scanPage.getResults().isEmpty() || scanPage.getResults().size() > 1) {
            throw new RuntimeException(
                    format(
                            "Invalid number of query expressions returned: %s",
                            scanPage.getResults().size()));
        }
        return scanPage.getResults().get(0);
    }

    private UserCredentials getUserCredentials(
            DynamoDBQueryExpression<UserCredentials> queryExpression) {
        QueryResultPage<UserCredentials> scanPage =
                userCredentialsMapper.queryPage(UserCredentials.class, queryExpression);
        if (scanPage.getResults().isEmpty() || scanPage.getResults().size() > 1) {
            throw new RuntimeException(
                    format(
                            "Invalid number of query expressions returned: %s",
                            scanPage.getResults().size()));
        }
        return scanPage.getResults().get(0);
    }

    private static String hashPassword(String password) {
        return Argon2EncoderHelper.argon2Hash(password);
    }

    private void warmUp(String tableName) {
        dynamoDB.describeTable(tableName);
    }
}
