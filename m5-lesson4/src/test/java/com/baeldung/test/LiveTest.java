package com.baeldung.test;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

public class LiveTest {

    private static String APP_ROOT = "http://localhost:8081";

    @Test
    public void givenUser_whenGetAllUsers_thenForbidden() {
        final Response response = givenAuth("user", "pass").get(APP_ROOT + "/user");

        assertEquals(200, response.getStatusCode());
    }

    //

    private final RequestSpecification givenAuth(String username, String password) {
        return RestAssured.given()
            .auth()
            .preemptive()
            .basic(username, password);
    }

}