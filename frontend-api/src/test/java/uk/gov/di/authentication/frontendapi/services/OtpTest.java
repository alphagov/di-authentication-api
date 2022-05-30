package uk.gov.di.authentication.frontendapi.services;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class OtpTest {

    @Test
    void testTOTPCode() {
        Otp otp = new Otp();

        assertTrue(otp.authorize("", 135441));
    }
}
