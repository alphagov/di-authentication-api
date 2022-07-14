package uk.gov.di.authentication.deliveryreceiptsapi.entity;

import uk.gov.di.authentication.shared.entity.TemplateAware;

public enum EmailNotificationType implements TemplateAware {
    VERIFY_EMAIL("VERIFY_EMAIL", "VERIFY_EMAIL_TEMPLATE_ID"),
    RESET_PASSWORD("RESET_PASSWORD_EMAIL", "RESET_PASSWORD_TEMPLATE_ID"),
    PASSWORD_RESET_CONFIRMATION(
            "PASSWORD_RESET_CONFIRMATION_EMAIL", "PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID"),
    ACCOUNT_CREATED_CONFIRMATION(
            "ACCOUNT_CREATED_CONFIRMATION_EMAIL", "ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID"),
    RESET_PASSWORD_WITH_CODE(
            "RESET_PASSWORD_WITH_CODE_EMAIL", "RESET_PASSWORD_WITH_CODE_TEMPLATE_ID"),
    EMAIL_UPDATED("EMAIL_UPDATED_EMAIL", "EMAIL_UPDATED_TEMPLATE_ID"),
    DELETE_ACCOUNT("DELETE_ACCOUNT_EMAIL", "DELETE_ACCOUNT_TEMPLATE_ID"),
    PHONE_NUMBER_UPDATED("PHONE_NUMBER_UPDATED_EMAIL", "PHONE_NUMBER_UPDATED_TEMPLATE_ID"),
    PASSWORD_UPDATED("PASSWORD_UPDATED_EMAIL", "PASSWORD_UPDATED_TEMPLATE_ID");

    private final String templateAlias;
    private final String templateName;

    EmailNotificationType(String templateAlias, String templateName) {
        this.templateAlias = templateAlias;
        this.templateName = templateName;
    }

    public String getTemplateId() {
        return System.getenv(templateName);
    }

    public String getTemplateAlias() {
        return templateAlias;
    }

    public static String findByTemplateId(String templateID) {
        for (EmailNotificationType type : values()) {
            if (type.getTemplateId().equals(templateID)) {
                return type.getTemplateAlias();
            }
        }
        return null;
    }
}
