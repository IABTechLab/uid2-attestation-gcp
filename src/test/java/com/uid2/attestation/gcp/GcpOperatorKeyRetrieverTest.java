package com.uid2.attestation.gcp;


import org.junit.Test;

import static org.junit.Assert.*;

public class GcpOperatorKeyRetrieverTest {

    @Test(expected = IllegalArgumentException.class)
    public void testIllegalInput_Null(){
        var sut = new GcpOperatorKeyRetriever(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIllegalInput_Empty(){
        var sut = new GcpOperatorKeyRetriever("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIllegalInput_BadFormat(){
        var sut = new GcpOperatorKeyRetriever("projects/123/secrets/s1");
    }

    @Test()
    public void testIllegalInput_GoodFormat(){
        var sut = new GcpOperatorKeyRetriever("projects/123/secrets/s1/versions/v1");
    }
}
