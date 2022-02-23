package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ClientStartInfo {

    @JsonProperty("clientName")
    private String clientName;

    @JsonProperty("scopes")
    private List<String> scopes;

    @JsonProperty("serviceType")
    private String serviceType;

    @JsonProperty("cookieConsentShared")
    private boolean cookieConsentShared;

    public ClientStartInfo(
            @JsonProperty(required = true, value = "clientName") String clientName,
            @JsonProperty(required = true, value = "scopes") List<String> scopes,
            @JsonProperty(required = true, value = "serviceType") String serviceType,
            @JsonProperty(value = "cookieConsentShared") boolean cookieConsentShared) {
        this.clientName = clientName;
        this.scopes = scopes;
        this.serviceType = serviceType;
        this.cookieConsentShared = cookieConsentShared;
    }

    public String getClientName() {
        return clientName;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public String getServiceType() {
        return serviceType;
    }

    public boolean getCookieConsentShared() {
        return cookieConsentShared;
    }
}